/*
 *        __  __           _   _           ____
 *   ___ / _|/ _| ___  ___| |_(_)_   _____/ ___|  __ _ _ __
 *  / _ \ |_| |_ / _ \/ __| __| \ \ / / _ \___ \ / _` | '_ \
 * |  __/  _|  _|  __/ (__| |_| |\ V /  __/___) | (_| | | | |
 *  \___|_| |_|  \___|\___|\__|_| \_/ \___|____/ \__,_|_| |_|
 *
 * Gregory J. Duck.
 *
 * Copyright (c) 2018 The National University of Singapore.
 * All rights reserved.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See the LICENSE file for details.
 */

/*
 * This is the EffectiveSan LLVM IR pass.  It is responsible for:
 * - Inserting type and bounds instrumentation
 * - Replacing memory allocation (heap/stack/global) with a "typed" version
 * - Generating type meta data.
 *
 * For more information, see the paper:
 *     Gregory J. Duck and Roland H. C. Yap. 2018. EffectiveSan: Type and
 *     Memory Error Detection using Dynamically Typed C/C++.  In Proceedings
 *     of 39th ACM SIGPLAN Conference on Programming Language Design and
 *     Implementation (PLDI’18). ACM, New York, NY, USA, 15 pages.
 *     https://doi.org/10.1145/3192366.3192388
 */

#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#pragma clang diagnostic ignored "-Wc99-extensions"

#include <cassert>
#include <cstdio>
#include <cstring>

#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <cxxabi.h>

#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MD5.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Transforms/Utils/Local.h"

extern "C"
{
    #include "effective.h"
    #include "lowfat_config.inc"
}

// #define EFFECTIVE_INSTRUMENTATION_DEBUG 1
// #define EFFECTIVE_LAYOUT_DEBUG  1

#ifndef EFFECTIVE_INSTRUMENTATION_DEBUG
#define EFFECTIVE_DEBUG_PRINT(...)      /* NOP */
#else
#define EFFECTIVE_DEBUG_PRINT(msg, ...) fprintf(stderr, (msg), ##__VA_ARGS__)
#endif

#define EFFECTIVE_FATAL_ERROR(message)                          \
    llvm::report_fatal_error(message, /*GenCrashDiag=*/false)

#define EFFECTIVE_LOG2(x)               (64 - clzll((x)-1))
#define EFFECTIVE_BSWAP64(x)            __builtin_bswap64(x)
#define EFFECTIVE_CLZLL(x)              clzll(x)

#define TYPE_META_PREFIX                "EFFECTIVE_TYPE_"
#define TYPE_INFO_PREFIX                "EFFECTIVE_INFO_"

#define BASIC_TYPE_TAG                  "EFFECTIVE_BASIC_TYPE_"
#define ENUM_TYPE_TAG                   "EFFECTIVE_ENUM_TYPE_"
#define POINTER_TYPE_TAG                "EFFECTIVE_POINTER_TYPE_"
#define STRUCT_TYPE_TAG                 "EFFECTIVE_STRUCT_TYPE_"
#define CLASS_TYPE_TAG                  "EFFECTIVE_CLASS_TYPE_"
#define UNION_TYPE_TAG                  "EFFECTIVE_UNION_TYPE_"
#define FUNCTION_TYPE_TAG               "EFFECTIVE_FUNCTION_TYPE_"
#define NEW_ARRAY_TYPE_TAG              "EFFECTIVE_NEW_ARRAY_TYPE_"
#define VPTR_TYPE_TAG                   "EFFECTIVE_VPTR_TYPE_"
#define LAYOUT_TAG                      "EFFECTIVE_LAYOUT_"

/*
 * Fool-proof "leading zero count" implementation.  Also works for "0".
 */
static size_t clzll(uint64_t x)
{
    if (x == 0)
        return 64;
    uint64_t bit = (uint64_t)1 << 63;
    size_t count = 0;
    while ((x & bit) == 0)
    {
        count++;
        bit >>= 1;
    }
    return count;
}

/*
 * Hash value.
 */
union HashVal
{
    uint8_t i8[16];
    uint16_t i16[8];
    uint32_t i32[4];
    uint64_t i64[2];
};

struct HashContext
{
    llvm::MD5 cxt;
};

static void update(HashContext &Cxt, const char *data, size_t len)
{
    llvm::ArrayRef<uint8_t> array((const uint8_t *)data, len);
    Cxt.cxt.update(array);
}

static HashVal final(HashContext &Cxt)
{
    HashVal val;
    Cxt.cxt.final(val.i8);
    return val;
}

/*
 * Type information.
 */
struct TypeEntry
{
    bool isInt8;                // Type is int8_t;
    std::string name;           // Type human-readable name.
    HashVal hash;               // Type hash value.
    llvm::Constant *typeMeta;   // Type meta-data value.
};
typedef std::map<llvm::DIType *, TypeEntry> TypeCache;
typedef std::map<llvm::DIType *, std::string> TypeNames;
typedef std::map<llvm::DIType *, llvm::Constant *> TypeInfos;
typedef std::map<llvm::DIType *, HashVal> TypeHashes;

struct TypeInfo
{
    TypeCache cache;
    TypeNames names;
    TypeInfos infos;
    TypeHashes hashes;
};

/*
 * Layout information.
 */
struct LayoutEntry
{
    size_t offset;
    llvm::DIType *type;
    uint64_t hash;
    uint64_t finalHash;
    intptr_t lb;
    intptr_t ub;
    bool priority;
    bool deleted;
};
typedef std::multimap<size_t, LayoutEntry> LayoutInfo;
typedef std::map<size_t, LayoutEntry *> FlattenedLayoutInfo;

/*
 * Type/bounds check information.
 */
struct CheckEntry
{
    llvm::Value *bounds;
    llvm::DIType *allocType;
    size_t allocSize;
};
typedef std::map<llvm::Value *, CheckEntry> CheckInfo;

typedef std::map<llvm::Value *, llvm::Value *> ValueInfo;

struct BoundsEntry
{
    llvm::Value *bounds;
    ssize_t lb;             // Sub-object LB
    ssize_t ub;             // Sub-object UB
};
typedef std::map<llvm::Value *, BoundsEntry> BoundsInfo;


struct BoundsCheckEntry
{
    llvm::Value *ptr;
    llvm::Instruction *instr;

    llvm::Value *widePtr;
    intptr_t wideLb;
    intptr_t wideUb;

    ssize_t accessOffset;
    size_t accessSize;
    llvm::Value *accessVarSize;     // For variable-sized access.

    bool redundant;
};
typedef std::map<llvm::Value *, std::vector<BoundsCheckEntry>>
    BoundsCheckInfo;

/*
 * Flexible Array Members (FAMs).
 */
struct FAM
{
    llvm::DIType *type;
    size_t offset;
};

/*
 * Insertion point.
 */
struct InsertPoint
{
    llvm::BasicBlock *bb;
    llvm::BasicBlock::iterator itr;
};

/*
 * Options.
 */
static llvm::cl::opt<bool> option_no_escapes("effective-no-escapes",
    llvm::cl::desc("Do not instrument pointer escapes"));
static llvm::cl::opt<bool> option_no_globals("effective-no-globals",
    llvm::cl::desc("Do not instrument global variables"));
static llvm::cl::opt<bool> option_no_stack("effective-no-stack",
    llvm::cl::desc("Do not instrument stack objects"));
static llvm::cl::opt<std::string> option_blacklist("effective-blacklist",
    llvm::cl::desc("Do not instrument code based on the given blacklist"),
    llvm::cl::init("-"));
static llvm::cl::opt<bool> option_warnings("effective-warnings",
    llvm::cl::desc("Enable warning messages"));
static llvm::cl::opt<unsigned> option_max_sub_objs("effective-max-sub-objs",
    llvm::cl::desc("Maximum number of allowable sub-objects per type"),
    llvm::cl::init(10000));
static llvm::cl::opt<bool> option_debug("effective-debug",
    llvm::cl::desc("Enable debug output"));

/*
 * Pre-defined types and objects.
 */
static llvm::Type *BoundsTy          = nullptr;
static llvm::StructType *EntryTy     = nullptr;
static llvm::StructType *TypeTy      = nullptr;
static llvm::StructType *InfoTy      = nullptr;
static llvm::StructType *InfoEntryTy = nullptr;
static llvm::StructType *ObjMetaTy   = nullptr;
static llvm::Constant *EmptyEntry    = nullptr;
static llvm::Constant *Int8TyMeta    = nullptr;
static llvm::Constant *BoundsNonFat  = nullptr;
static llvm::DIType *Int8Ty          = nullptr;
static llvm::DIType *Int16Ty         = nullptr;
static llvm::DIType *Int32Ty         = nullptr;
static llvm::DIType *Int64Ty         = nullptr;
static llvm::DIType *Int128Ty        = nullptr;
static llvm::DIType *Int8PtrTy       = nullptr;

static llvm::Module *Module = nullptr;  // Used by normalizePointerType()
                                        // (not ideal but too messy to fix).

static std::unique_ptr<llvm::SpecialCaseList> Blacklist = nullptr;

static std::map<size_t, llvm::StructType *> metaCache;
static std::map<size_t, llvm::StructType *> infoCache;

/*
 * Prototypes.
 */
static llvm::DIType *normalizeType(llvm::DIType *Ty);
static void buildMemberLayout(llvm::DIType *Ty, size_t offset, const FAM &fam,
    intptr_t lb, intptr_t ub, bool priority, bool inherited, TypeInfo &tInfo,
    LayoutInfo &layout);
static void buildTypeHumanName(llvm::DIType *Ty, std::string &humanName,
    TypeInfo &tInfo);
static HashVal buildTypeHash(llvm::DIType *Ty, TypeInfo &tInfo);
static std::pair<intptr_t, intptr_t> calculateBoundsConstant(
    const llvm::DataLayout &DL, llvm::Constant *Ptr);
static const BoundsEntry &calculateBounds(llvm::Module &M, llvm::Function &F,
    llvm::Value *Ptr, TypeInfo &tInfo, CheckInfo &cInfo, BoundsInfo &bInfo);
static bool canInstrumentGlobal(llvm::GlobalVariable &GV);

/*
 * Test if something is blacklisted or not.
 */
static bool isBlacklisted(const char *section, llvm::StringRef Name)
{
    if (Blacklist == nullptr)
        return false;
    if (Blacklist->inSection(section, Name))
        return true;
    return false;
}

/*
 * Test if a type represents a vptr or not.
 */
static bool isVPtrType(llvm::DIType *Ty)
{
    auto DerivedTy = llvm::dyn_cast<llvm::DIDerivedType>(Ty);
    if (DerivedTy == nullptr)
        return false;
    if (DerivedTy->getTag() != llvm::dwarf::DW_TAG_member)
        return false;
    llvm::StringRef name = DerivedTy->getName();
    const char prefix[] = "_vptr$";
    return (name.str().compare(0, sizeof(prefix)-1, prefix) == 0);
}

/*
 * Test if a type represents a C++ new[] wrapper.
 */
static bool isNewArrayType(llvm::DIType *Ty)
{
    if (Ty == nullptr)
        return false;
    auto CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty);
    if (CompositeTy == nullptr)
        return false;
    if (CompositeTy->getTag() != llvm::dwarf::DW_TAG_structure_type)
        return false;
    llvm::StringRef name = CompositeTy->getName();
    const char prefix[] = "new ";
    return (name.str().compare(0, sizeof(prefix)-1, prefix) == 0);
}

/*
 * Test if a type is anonymous or not.
 */
static bool isAnonymousType(llvm::DIType *Ty)
{
    auto CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty);
    if (CompositeTy == nullptr)
        return false;
    switch (CompositeTy->getTag())
    {
    case llvm::dwarf::DW_TAG_structure_type:
    case llvm::dwarf::DW_TAG_class_type:
    case llvm::dwarf::DW_TAG_union_type:
        break;
    default:
        return false;
    }
    llvm::StringRef name = CompositeTy->getName();
    if (name != "")
        return false;
    llvm::StringRef ident = CompositeTy->getIdentifier();
    if (ident == "")
        return true;
    if (ident.size() >= 4 && ident[0] == '_' && ident[1] == 'Z' &&
            ident[2] == 'T' && ident[3] == 'S' &&
            ident.find("Ut", 4) != std::string::npos)
    {
        int status = 0;
        char* res = abi::__cxa_demangle(ident.str().c_str(), NULL, NULL,
            &status);
        if (status != 0)
            return false;
        bool isAnon = (strstr(res, "unnamed type#") != NULL);
        free(res);
        return isAnon;
    }
    return false;
}

/*
 * Normalize an integer type.
 */
static llvm::DIType *normalizeIntegerType(llvm::DIType *Ty)
{
    if (Ty == nullptr)
        return Int8Ty;
    if (auto *BasicTy = llvm::dyn_cast<llvm::DIBasicType>(Ty))
    {
        switch (BasicTy->getEncoding())
        {
        case llvm::dwarf::DW_ATE_signed_char:
        case llvm::dwarf::DW_ATE_unsigned_char:
        case llvm::dwarf::DW_ATE_boolean:
            return Int8Ty;
        case llvm::dwarf::DW_ATE_signed:
        case llvm::dwarf::DW_ATE_unsigned:
        case llvm::dwarf::DW_ATE_UTF:
            switch (BasicTy->getSizeInBits())
            {
            case 8:
                return Int8Ty;
            case 16:
                return Int16Ty;
            case 32:
                return Int32Ty;
            case 64:
                return Int64Ty;
            case 128:
                return Int128Ty;
            default:
                return Ty;
            }
        default:
            return Ty;
        }
    }
    else if (auto *CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty))
    {
        if (CompositeTy->getTag() == llvm::dwarf::DW_TAG_enumeration_type)
            return Int32Ty;
        else
            return Ty;
    }
    else
        return Ty;
}

/*
 * Normalize a pointer type.
 */
static llvm::DIType *normalizePointerType(llvm::DIType *Ty)
{
    if (Ty == nullptr)
        return Int8PtrTy;
    auto DerivedTy = llvm::dyn_cast<llvm::DIDerivedType>(Ty);
    if (DerivedTy == nullptr)
        return Int8PtrTy;
    switch (DerivedTy->getTag())
    {
    case llvm::dwarf::DW_TAG_pointer_type:
    case llvm::dwarf::DW_TAG_reference_type:
    case llvm::dwarf::DW_TAG_rvalue_reference_type:
        break;
    default:
        return Int8PtrTy;
    }
    Ty = DerivedTy->getBaseType().resolve();
    if (Ty == nullptr)
        return Int8PtrTy;
    Ty = normalizeType(Ty);
    llvm::DIBuilder builder(*Module);
    Ty = builder.createPointerType(Ty, sizeof(void *)*CHAR_BIT);
    return Ty;
}

/*
 * "Normalize" a type.
 */
static llvm::DIType *normalizeType(llvm::DIType *Ty)
{
    while (Ty != nullptr)
    {
        if (isVPtrType(Ty))
            return Int8PtrTy;
        else if (llvm::isa<llvm::DIBasicType>(Ty))
            return normalizeIntegerType(Ty);
        else if (auto *DerivedTy = llvm::dyn_cast<llvm::DIDerivedType>(Ty))
        {
            switch (DerivedTy->getTag())
            {
            case llvm::dwarf::DW_TAG_ptr_to_member_type:
            {
                // C++ pointers-to-member types are treated as size_t.
                return Int64Ty;
            }
            case llvm::dwarf::DW_TAG_typedef:
            case llvm::dwarf::DW_TAG_member:
            case llvm::dwarf::DW_TAG_inheritance:
            case llvm::dwarf::DW_TAG_const_type:
            case llvm::dwarf::DW_TAG_volatile_type:
            case llvm::dwarf::DW_TAG_atomic_type:
            case llvm::dwarf::DW_TAG_restrict_type:
                break;
            case llvm::dwarf::DW_TAG_pointer_type:
            case llvm::dwarf::DW_TAG_reference_type:
            case llvm::dwarf::DW_TAG_rvalue_reference_type:
                return normalizePointerType(Ty);
            default:
                return Ty;
            }
            Ty = DerivedTy->getBaseType().resolve();
        }
        else if (auto *CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty))
        {
            switch (CompositeTy->getTag())
            {
            case llvm::dwarf::DW_TAG_enumeration_type:
                return Int32Ty;
            case llvm::dwarf::DW_TAG_array_type:
                Ty = CompositeTy->getBaseType().resolve();
                break;
            default:
                return Ty;
            }
        }
        else
            return Ty;
    }
    return Int8Ty;      // Give up
}

/*
 * Determine if two types are equivalent or not.  Note that this function
 * need not be complete, since it is only used for optimization.  It
 * currently does not handle some tricky cases like anonymous types.
 */
static bool isTypeEquivalent(llvm::DIType *Ty1, llvm::DIType *Ty2)
{
    if (Ty1 == Ty2)
        return true;
    Ty1 = normalizeType(Ty1);
    Ty2 = normalizeType(Ty2);
    if (Ty1 == Ty2)
        return true;
    if (Ty1 == nullptr || Ty2 == nullptr)
        return false;
    auto *BasicTy1 = llvm::dyn_cast<llvm::DIBasicType>(Ty1);
    auto *BasicTy2 = llvm::dyn_cast<llvm::DIBasicType>(Ty2);
    if (BasicTy1 != nullptr && BasicTy2 != nullptr)
    {
        if (BasicTy1->getSizeInBits() != BasicTy2->getSizeInBits())
            return false;
        unsigned encoding = BasicTy1->getEncoding();
        switch (encoding)
        {
        case llvm::dwarf::DW_ATE_signed_char:
        case llvm::dwarf::DW_ATE_unsigned_char:
        case llvm::dwarf::DW_ATE_boolean:
            encoding = llvm::dwarf::DW_ATE_signed_char;
            break;
        case llvm::dwarf::DW_ATE_signed:
        case llvm::dwarf::DW_ATE_unsigned:
        case llvm::dwarf::DW_ATE_UTF:
            encoding = llvm::dwarf::DW_ATE_signed;
            break;
        default:
            break;
        }
        switch (BasicTy2->getEncoding())
        {
        case llvm::dwarf::DW_ATE_signed_char:
        case llvm::dwarf::DW_ATE_unsigned_char:
        case llvm::dwarf::DW_ATE_boolean:
            return (encoding == llvm::dwarf::DW_ATE_signed_char);
        case llvm::dwarf::DW_ATE_signed:
        case llvm::dwarf::DW_ATE_unsigned:
        case llvm::dwarf::DW_ATE_UTF:
            return (encoding == llvm::dwarf::DW_ATE_signed);
        default:
            return (encoding == BasicTy2->getEncoding());
        }
    }
    auto *DerivedTy1 = llvm::dyn_cast<llvm::DIDerivedType>(Ty1);
    auto *DerivedTy2 = llvm::dyn_cast<llvm::DIDerivedType>(Ty2);
    if (DerivedTy1 != nullptr && DerivedTy2 != nullptr)
    {
        switch (DerivedTy1->getTag())
        {
        case llvm::dwarf::DW_TAG_pointer_type:
        case llvm::dwarf::DW_TAG_reference_type:
        case llvm::dwarf::DW_TAG_rvalue_reference_type:
            break;
        default:
            return false;
        }
        switch (DerivedTy2->getTag())
        {
        case llvm::dwarf::DW_TAG_pointer_type:
        case llvm::dwarf::DW_TAG_reference_type:
        case llvm::dwarf::DW_TAG_rvalue_reference_type:
            return isTypeEquivalent(DerivedTy1->getBaseType().resolve(),
                              DerivedTy2->getBaseType().resolve());
        default:
            return false;
        }
    }
    return false;
}

/*
 * Get a type's size in bytes.
 */
static size_t getSizeOfType(llvm::DIType *Ty)
{
    size_t size = Ty->getSizeInBits() / CHAR_BIT;
    return size;
}

/*
 * Get T from a T[N] type, else return nullptr.
 */
static llvm::DIType *getArrayElementType(llvm::DIType *Ty)
{
    if (Ty == nullptr)
        return nullptr;
    auto *CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty);
    if (CompositeTy == nullptr)
        return nullptr;
    if (CompositeTy->getTag() != llvm::dwarf::DW_TAG_array_type)
        return nullptr;
    return CompositeTy->getBaseType().resolve();
}

/*
 * Get the inner sub-range of a (multidim) array.
 */
static std::pair<ssize_t, ssize_t> getArrayRange(llvm::DIType *Ty)
{
    auto EMPTY = std::make_pair<ssize_t, ssize_t>(1, 0);
    if (Ty == nullptr)
        return EMPTY;
    auto *CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty);
    if (CompositeTy == nullptr)
        return EMPTY;
    if (CompositeTy->getTag() != llvm::dwarf::DW_TAG_array_type)
        return EMPTY;
    auto Elements = CompositeTy->getElements();
    if (Elements.size() < 1)
        return EMPTY;
    auto Element = Elements[Elements.size()-1];
    auto SubRange = llvm::dyn_cast<llvm::DISubrange>(Element);
    if (SubRange == nullptr)
        return EMPTY;
    return std::make_pair<ssize_t, ssize_t>(SubRange->getLowerBound(),
        SubRange->getCount());
}

/*
 * Get the composite type of a struct/class/union type, else return nullptr.
 */
static llvm::DICompositeType *getStructType(llvm::DIType *Ty)
{
    auto *CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty);
    if (CompositeTy == nullptr)
        return nullptr;
    switch (CompositeTy->getTag())
    {
    case llvm::dwarf::DW_TAG_structure_type:
    case llvm::dwarf::DW_TAG_class_type:
    case llvm::dwarf::DW_TAG_union_type:
        return CompositeTy;
    default:
        return nullptr;
    }
}

/*
 * Hash a string value.
 */
static HashVal hashString(const char *tag, const char *s)
{
    HashContext cxt;
    size_t len = strlen(tag);
    update(cxt, tag, len);
    len = strlen(s);
    update(cxt, s, len);
    return final(cxt);
}

/*
 * Hash a hash value.
 */
static HashVal hashHash(const char *tag, HashVal val)
{
    HashContext cxt;
    size_t len = strlen(tag);
    update(cxt, tag, len);
    update(cxt, (char *)val.i8, sizeof(val.i8));
    return final(cxt);
}

/*****************************************************************************/
/* WARNINGS                                                                  */
/*****************************************************************************/

class DiagnosticInfoEffectiveSan : public llvm::DiagnosticInfo
{
    private:
        static int DK;
        std::string msg;

    public:
        DiagnosticInfoEffectiveSan(const std::string &msg) :
            llvm::DiagnosticInfo(DK, llvm::DS_Warning), msg(msg) { }
        void print(llvm::DiagnosticPrinter &dp) const override;
        static void init()
        {
            DK = llvm::getNextAvailablePluginDiagnosticKind();
        }
};

int DiagnosticInfoEffectiveSan::DK = 0;

void DiagnosticInfoEffectiveSan::print(llvm::DiagnosticPrinter &dp) const
{
    dp << "[EffectiveSan] " << msg << "\n";
}

static void warning(llvm::Module &M, const std::string &msg)
{
    if (option_warnings)
        M.getContext().diagnose(DiagnosticInfoEffectiveSan(msg));
}

/*****************************************************************************/
/* META DATA                                                                 */
/*****************************************************************************/

/*
 * Type meta data generation.
 *
 * There are currently two kinds of type meta data:
 *  - EFFECTIVE_TYPE: is the type meta data used for type checking; and
 *  - EFFECTIVE_INFO: is the type meta data used for error messages.
 *
 * The "TYPE" version is used for runtime type checking so is designed for
 * speed, whereas the "INFO" version is designed for error messages.
 */

static llvm::StructType *makeTypeMetaType(llvm::Module &M, size_t len)
{
    auto i = metaCache.find(len);
    if (i != metaCache.end())
        return i->second;

    llvm::LLVMContext &Cxt = M.getContext();
    std::string name("EFFECTIVE_TYPE");
    if (len > 0)
    {
        name += '_';
        name += std::to_string(len);
    }
    llvm::StructType *Ty = llvm::StructType::create(Cxt, name);
    if (len == 0)
        TypeTy = Ty;
    std::vector<llvm::Type *> Fields;
    Fields.push_back(llvm::Type::getInt64Ty(Cxt));      /* hash */
    Fields.push_back(llvm::Type::getInt64Ty(Cxt));      /* hash2 */
    Fields.push_back(llvm::Type::getInt32Ty(Cxt));      /* size */
    Fields.push_back(llvm::Type::getInt32Ty(Cxt));      /* size_fam */
    Fields.push_back(llvm::Type::getInt32Ty(Cxt));      /* offset_fam */
    Fields.push_back(llvm::Type::getInt32Ty(Cxt));      /* sanity */
    Fields.push_back(llvm::Type::getInt64Ty(Cxt));      /* magic */
    Fields.push_back(llvm::Type::getInt64Ty(Cxt));      /* mask */
    Fields.push_back(InfoTy->getPointerTo());           /* info */
    Fields.push_back(llvm::Type::getInt64Ty(Cxt));      /* next */
    llvm::ArrayType *LayoutTy = llvm::ArrayType::get(EntryTy, len);
    Fields.push_back(LayoutTy);                         /* layout */
    Ty->setBody(Fields);

    metaCache.insert(std::make_pair(len, Ty));

    return Ty;
}

static llvm::StructType *makeTypeInfoType(llvm::Module &M, size_t len)
{
    auto i = infoCache.find(len);
    if (i != infoCache.end())
        return i->second;

    llvm::LLVMContext &Cxt = M.getContext();
    std::string name("EFFECTIVE_INFO");
    if (len > 0)
    {
        name += '_';
        name += std::to_string(len);
    }
    llvm::StructType *Ty = llvm::StructType::create(Cxt, name);
    if (len == 0)
        InfoTy = Ty;
    std::vector<llvm::Type *> Fields;
    Fields.push_back(llvm::Type::getInt8PtrTy(Cxt));    /* name */
    Fields.push_back(llvm::Type::getInt32Ty(Cxt));      /* size */
    Fields.push_back(llvm::Type::getInt32Ty(Cxt));      /* num_entries */
    Fields.push_back(llvm::Type::getInt32Ty(Cxt));      /* flags */
    Fields.push_back(InfoTy->getPointerTo());           /* next */
    llvm::ArrayType *EntriesTy = llvm::ArrayType::get(InfoEntryTy, len);
    Fields.push_back(EntriesTy);                        /* entries */
    Ty->setBody(Fields);

    infoCache.insert(std::make_pair(len, Ty));

    return Ty;
}

static TypeEntry &addTypeEntry(TypeInfo &tInfo, llvm::DIType *Ty,
    std::string &name, HashVal hash, llvm::Constant *Meta,
    bool isInt8 = false)
{
    TypeEntry entry = {isInt8, name, hash, Meta};
    auto i = tInfo.cache.insert(std::make_pair(Ty, entry));
    return i.first->second;
}

static uint64_t getTypeHash(llvm::DIType *Ty, HashVal hash)
{
    if (Ty == nullptr || Ty == Int8Ty)
        return EFFECTIVE_TYPE_INT8_HASH;
    if (Ty == Int8PtrTy)
        return EFFECTIVE_TYPE_INT8_PTR_HASH;
    return EFFECTIVE_BSWAP64(hash.i64[0]);
}

/*
 * If a type T can be coerced to another type U, then return a special hash
 * value representing (U)T.  Note that we do not return U's hash to prevent
 * transitive coercions, e.g. (int *) -> (void *) -> (float *).
 */
static uint64_t getCoercedTypeHash(llvm::DIType *Ty)
{
    if (auto *DerivedTy = llvm::dyn_cast<llvm::DIDerivedType>(Ty))
    {
        switch (DerivedTy->getTag())
        {
        case llvm::dwarf::DW_TAG_pointer_type:
        case llvm::dwarf::DW_TAG_reference_type:
        case llvm::dwarf::DW_TAG_rvalue_reference_type:
            return EFFECTIVE_COERCED_INT8_PTR_HASH;
        default:
            return EFFECTIVE_TYPE_NIL_HASH;
        }
    }
    return EFFECTIVE_TYPE_NIL_HASH;         
}

/*
 * Add an entry to the layout.
 */
static void addLayoutEntry(LayoutInfo &layout, TypeInfo &tInfo, size_t offset,
    llvm::DIType *Ty, intptr_t lb, intptr_t ub, bool priority)
{
    Ty = normalizeType(Ty);
    HashVal hash = buildTypeHash(Ty, tInfo);
    uint64_t hval = getTypeHash(Ty, hash);

    // Check for duplicate entries.  These can happen for unions, for example.
    auto range = layout.equal_range(offset);
    bool found = false;
    for (auto i = range.first; i != range.second; ++i)
    {
        if (i->second.hash == hval)
        {
            // Widen the bounds to accomodate both sub-objects.  This is not
            // ideal but better than not handling this case entirely.
            i->second.lb = std::min(i->second.lb, lb);
            i->second.ub = std::max(i->second.ub, ub);
            i->second.priority = false;
            found = true;
        }
    }
    if (found)
        return;

    // No existing entry, so create one:
#ifdef EFFECTIVE_LAYOUT_DEBUG
    std::string name;
    buildTypeHumanName(Ty, name, tInfo);
    fprintf(stderr, "\t%s [%+zd] (%zd..%zd) <%.16lX> {%zd} ", name.c_str(),
        offset, lb, ub, hval, (intptr_t)hval);
    Ty->dump();
#endif
    LayoutEntry entry = {offset, Ty, hval, 0, lb, ub, priority, false};
    layout.insert(std::make_pair(offset, entry));

    // Add entry for any type coercion:
    hval = getCoercedTypeHash(Ty);
    if (hval == EFFECTIVE_TYPE_NIL_HASH)
        return;
    found = false;
    for (auto i = range.first; i != range.second; ++i)
    {
        if (i->second.hash == hval)
        {
            i->second.lb = std::min(i->second.lb, lb);
            i->second.ub = std::max(i->second.ub, ub);
            found = true;
        }
    }
    if (found)
        return;

#ifdef EFFECTIVE_LAYOUT_DEBUG
    fprintf(stderr, "\t+coerced <%.16lX> {%zd}\n", hval, (intptr_t)hval);
#endif

    LayoutEntry coercedEntry = {offset, Ty, hval, 0, lb, ub, priority, false};
    layout.insert(std::make_pair(offset, coercedEntry));
}

/*
 * Get the "normalized" type of a struct/class member, and any additional
 * information about the member (bit-fielf, inheritance, etc.).  Does not
 * flatten arrays.
 */
static llvm::DIType *getMemberType(llvm::DIType *Ty, size_t &offset,
    bool &isStatic, bool &isBitField, bool &isInheritance, bool &isVirtual)
{
    while (true)
    {
        if (isVPtrType(Ty))
        {
            Ty = Int8PtrTy;
            break;
        }
        auto DerivedTy = llvm::dyn_cast<llvm::DIDerivedType>(Ty);
        if (DerivedTy == nullptr)
            break;
        if (DerivedTy->isStaticMember())
        {
            isStatic = true;
            break;
        }
        bool found = false;
        switch (DerivedTy->getTag())
        {
        case llvm::dwarf::DW_TAG_member:
            if (DerivedTy->isBitField())
            {
                // Special handling of bitfields: we want the offset of
                // the "containing" integer type.  Alternatively we could
                // just disallow pointers to bitfields altogether.
                llvm::Constant *Offset =
                    DerivedTy->getStorageOffsetInBits();
                if (Offset != nullptr &&
                    llvm::isa<llvm::ConstantInt>(Offset))
                {
                    auto *Int = llvm::dyn_cast<llvm::ConstantInt>(Offset);
                    offset += Int->getZExtValue();
                    Ty = DerivedTy->getBaseType().resolve();
                    Ty = normalizeIntegerType(Ty);
                    isBitField = true;
                    break;
                }
            }
            offset += DerivedTy->getOffsetInBits();
            Ty = DerivedTy->getBaseType().resolve();
            break;
        case llvm::dwarf::DW_TAG_inheritance:
            if (Ty->getFlags() & llvm::DINode::DIFlags::FlagVirtual)
                isVirtual = true;
            isInheritance = true;
            offset += DerivedTy->getOffsetInBits();
            Ty = DerivedTy->getBaseType().resolve();
            break;
        case llvm::dwarf::DW_TAG_typedef:
        case llvm::dwarf::DW_TAG_const_type:
        case llvm::dwarf::DW_TAG_volatile_type:
        case llvm::dwarf::DW_TAG_atomic_type:
        case llvm::dwarf::DW_TAG_restrict_type:
            Ty = DerivedTy->getBaseType().resolve();
            break;
        case llvm::dwarf::DW_TAG_ptr_to_member_type:
            Ty = Int64Ty;
            break;
        case llvm::dwarf::DW_TAG_pointer_type:
        case llvm::dwarf::DW_TAG_reference_type:
        case llvm::dwarf::DW_TAG_rvalue_reference_type:
            found = true;
            break;
        default:
            EFFECTIVE_FATAL_ERROR("unknown derived type");
        }
        if (found)
            break;
    }
    return normalizeIntegerType(Ty);
}

/*
 * Build a layout mapping offsets to (sub-)object types.  The layout itself is
 * represented as a multimap (since several different types can occupy the same
 * offset).  The representation is flattened later.
 */
static void buildLayout(llvm::DICompositeType *CompositeTy, size_t offsetBase,
    const FAM &fam, TypeInfo &tInfo, LayoutInfo &layout, bool priority = true,
    bool inherited = false)
{
    llvm::DINodeArray Elements = CompositeTy->getElements();
    for (auto Element: Elements)
    {
        if (llvm::isa<llvm::DISubprogram>(Element) ||
            llvm::isa<llvm::DIEnumerator>(Element))
        {
            // [SIMPLIFICATION]
            // Methods and scoped type declarations are not considered part
            // of the type.
            continue;
        }
        auto *Ty = llvm::dyn_cast<llvm::DIType>(Element);
        if (Ty == nullptr)
            EFFECTIVE_FATAL_ERROR("non-type element");
        size_t offset = offsetBase * CHAR_BIT;
        bool isStatic = false, isBitField = false, isInheritance = false,
             isVirtual = false;
        Ty = getMemberType(Ty, offset, isStatic, isBitField, isInheritance,
            isVirtual);
        if (Ty == nullptr)
            continue;
        if (inherited && isVirtual)
        {
            // [SIMPLIFICATION]
            // Virtual inheritance is implemented using the virtual function
            // table, so is not part of the type (for our purposes).
            continue;
        }

        if (offset % CHAR_BIT != 0)
            EFFECTIVE_FATAL_ERROR("offset is not byte aligned");

        if (isStatic)
        {
            // [SIMPLIFICATION]
            // Static members are not considered part of the type.
            continue;
        }

        size_t size = getSizeOfType(Ty);
        offset = offset / CHAR_BIT;
        intptr_t lb = 0, ub = size;
        buildMemberLayout(Ty, offset, fam, lb, ub, priority,
            (inherited || isInheritance), tInfo, layout);
    }
}

/*
 * Build the layout for a struct member, possibly recursively if the
 * member itself is a composite type.  Here lb..ub represent the array bounds.
 * For non-array types T, the bounds are simply 0..sizeof(T).
 */
static void buildMemberLayout(llvm::DIType *Ty, size_t offset, const FAM &fam,
    intptr_t lb, intptr_t ub, bool priority, bool inherited, TypeInfo &tInfo,
    LayoutInfo &layout)
{
    if (offset == fam.offset && Ty == fam.type)
    {
        // Special handling of the Flexible Array Member (FAM), if any.
        // It is left to effective_type_check() to set the correct lb.
        Ty = normalizeType(Ty);
        intptr_t lb = -EFFECTIVE_DELTA, ub = EFFECTIVE_DELTA;
        addLayoutEntry(layout, tInfo, offset, Ty, lb, ub, priority);
        auto *CompositeTy = getStructType(Ty);
        if (CompositeTy != nullptr)
            buildLayout(CompositeTy, offset, fam, tInfo, layout,
                /*priority=*/false, /*inherited=*/false);
        return;
    }

    auto *ElemTy = getArrayElementType(Ty);
    if (ElemTy == nullptr)
    {
        // This is a non-array member; so we just add an entry for Ty:
        Ty = normalizeType(Ty);
        auto *CompositeTy = getStructType(Ty);
        addLayoutEntry(layout, tInfo, offset, Ty, lb, ub,
            (priority || CompositeTy != nullptr));

        // If `Ty' is a struct type, then recursively build the layout:
        if (CompositeTy != nullptr)
            buildLayout(CompositeTy, offset, fam, tInfo, layout,
                /*priority=*/false, inherited);
    }
    else
    {
        // This is an array member of type ElemTy[N]; so we must add an
        // entry for each array element.
        ElemTy = normalizeType(ElemTy);
        auto arrayRange = getArrayRange(Ty);
        size_t arraySize = getSizeOfType(Ty);
        if (arraySize == 0 || arrayRange.first >= arrayRange.second)
        {
            // Empty array, so no work to do:
            return;
        }
        if (arrayRange.first != 0)
        {
            // Don't know how to handle this case, so give up:
            return;
        }
        size_t arraySpan = arrayRange.second;
        size_t elemSize = getSizeOfType(ElemTy);
        assert(elemSize != 0);

        // [SIMPLIFICATION]
        // We treat T[A][B]...[Y][Z] as T[A*B*...*Y][Z], i.e. bounds are
        // restricted to the inner most array.  This is because EffectiveSan
        // can only type check against the incomplete type T[], thus the
        // simplification is sufficient.

        intptr_t lb = 0, ub = arraySpan * elemSize;
        for (size_t i = 0; i < arraySize; i += ub)
        {
            for (size_t j = 0; j < arraySpan; j++)
            {
                size_t elemOffset = j * elemSize;
                size_t subArrayOffset = i + j * elemSize;
                bool newPriority = (i == 0 && j == 0);
                buildMemberLayout(ElemTy, offset + subArrayOffset, fam,
                    lb - elemOffset, ub - elemOffset, newPriority,
                    /*inherited=*/false, tInfo, layout);
            }
        }
    }
}

/*
 * If the layout is too big, purge some entries.
 */
static bool shrinkLayoutToFit(LayoutInfo &layout, size_t max)
{
    size_t size = layout.size();
    if (size <= max)
        return true;

    // STEP #1: Delete non-priority char[] entries:
    for (auto &entry: layout)
    {
        LayoutEntry &lEntry = entry.second;
        if (!lEntry.priority && lEntry.type == Int8Ty)
        {
            lEntry.deleted = true;
            size--;
            if (size <= max)
                return true;
        }
    }

    // STEP #2: Delete any non-priority entry:
    for (auto &entry: layout)
    {
        LayoutEntry &lEntry = entry.second;
        if (!lEntry.priority)
        {
            lEntry.deleted = true;
            size--;
            if (size <= max)
                return true;
        }
    }

    // Failure...
    return false;
}

/*
 * Decide how big the layout array for the type meta data should be.  Must
 * satisfy the following:
 * - Must be a power-of-two.
 * - Aim for the layout to be 20-35% full.
 *   Any higher = too many collisions.
 *   Any lower = waste space.
 */
static size_t getLayoutLength(const LayoutInfo &layout)
{
    size_t len = layout.size();
    if (len > option_max_sub_objs)
        len = option_max_sub_objs;
    size_t log2len = EFFECTIVE_LOG2(len);
    size_t len2 = (size_t)2 << log2len;
    double LB = 0.20;       // 20% full
    double UB = 0.35;       // 35% full
    while ((double)len / (double)len2 < LB)
        len2 /= 2;
    while ((double)len / (double)len2 > UB)
        len2 *= 2;
    double full = ((double)len / (double)len2);
    if (full > UB)
    {
        EFFECTIVE_DEBUG_PRINT("warning: sub-optimal hash table size: "
            "[%zu ---> %zu] (%.2f%%)\n", len, len2,
            ((double)len / (double)len2) * 100.0);
    }
    return len2;
}

/*
 * If there are too many collisions building the layout hash table, we try a
 * new hash value or make the layout larger.  This function decides what to
 * do.
 */
static uint64_t getNextLayoutHash(HashVal hash, unsigned i, uint64_t hval,
    size_t layoutLen)
{
    HashContext cxt;
    update(cxt, (char *)hash.i8, sizeof(hash.i8));
    update(cxt, (char *)&hval, sizeof(hval));
    update(cxt, (char *)&layoutLen, sizeof(layoutLen));
    update(cxt, (char *)&i, sizeof(i));
    hval = final(cxt).i64[0];

    return hval;
}

/*
 * Put a layout entry into the "flattened" layout representation.  Resolves
 * collisions using `linear probing', meaning that we place in the first
 * available free slot starting from the original position.  This function
 * also ensures that no more than EFFECTIVE_MAX_PROBE contigious slots are
 * used.
 *
 * "Priority" entries are deemed more likely to be used by a type check,
 * so we try to place then as closely as possible to the original position.
 */
static bool placeFlattenedLayoutEntry(FlattenedLayoutInfo &flattenedLayout,
    uint64_t hval1, size_t offset, uint64_t mask, LayoutEntry &lEntry)
{
    if (lEntry.deleted)
        return true;

    uint64_t hval2 = lEntry.hash;
    size_t hval = EFFECTIVE_HASH(hval1, hval2, offset);
    ssize_t idx = (ssize_t)(hval & mask);
    bool priority = lEntry.priority;

    lEntry.finalHash = hval;

    // (1) Find a free slot: 
    size_t count = 0;
    size_t i = 0;
    for (i = 0; i < EFFECTIVE_MAX_PROBE; i++)
    {
        count++;
        size_t eidx = idx + i;
        auto j = flattenedLayout.find(eidx);
        if (j == flattenedLayout.end())
        {
#ifdef EFFECTIVE_LAYOUT_DEBUG
            fprintf(stderr, "ADD(0x%.16lX, 0x%.16lX, %zu) = "
                "0x%.16lX {%zd} [%zd..%zd] index=%zu\n", hval1, hval2, offset,
                hval, (ssize_t)hval, offset + lEntry.lb, offset + lEntry.ub,
                eidx);
#endif
            flattenedLayout.insert(std::make_pair(eidx, &lEntry));
            break;
        }
        else if (priority && !j->second->priority)
        {
            // This is a "priority" entry, so we boot out any older
            // "non-priority" entry:
            LayoutEntry *oldEntry = j->second;
            flattenedLayout.erase(eidx);
            flattenedLayout.insert(std::make_pair(eidx, &lEntry));
            return placeFlattenedLayoutEntry(flattenedLayout,
                hval1, oldEntry->offset, mask, *oldEntry);
        }
        if (&lEntry == j->second)
        {
            EFFECTIVE_DEBUG_PRINT("warning: duplicate entry detected\n");
            return true;
        }
    }

    // (2) Check there are no sequences of full slots > EFFECTIVE_MAX_PROBE:
    for (i++; count < EFFECTIVE_MAX_PROBE; i++)
    {
        size_t eidx = idx + i;
        auto j = flattenedLayout.find(eidx);
        if (j == flattenedLayout.end())
            break;
        count++;
    }
    for (ssize_t i = 1; idx - i >= 0 && count < EFFECTIVE_MAX_PROBE; i++)
    {
        size_t eidx = idx - i;
        auto j = flattenedLayout.find(eidx);
        if (j == flattenedLayout.end())
            break;
        count++;
    }
    if (count < EFFECTIVE_MAX_PROBE)
        return true;

    // Failed to place layout entry.
    return false;
}

/*
 * Compile the given layout to the low-level LLVM representation.  Note that
 * this process may fail if there are too many collisions, in which case we
 * tweak the parameters and try, try again.
 */
static std::pair<llvm::Constant *, size_t> compileLayout(llvm::Module &M,
    uint64_t hval, size_t layoutLen, LayoutInfo &layout)
{
    // Step (1): Flatten the layout:
    FlattenedLayoutInfo flattenedLayout;
    uint64_t mask = layoutLen - 1;
    for (auto &entries: layout)
    {
        size_t offset = entries.first;
        LayoutEntry &lEntry = entries.second;
        if (!placeFlattenedLayoutEntry(flattenedLayout, hval, offset, mask,
                lEntry))
        {
            // We have failed to build a suitable layout (too many
            // collisions), so try again:
            return std::make_pair(nullptr, 0);
        }
    }

#ifdef EFFECTIVE_LAYOUT_DEBUG
    // Step (2): Verify the layout:
    for (auto &entries: layout)
    {
        size_t offset = entries.first;
        LayoutEntry &lEntry = entries.second;
        uint64_t hval2 = lEntry.hash;
        uint64_t hash = EFFECTIVE_HASH(hval, hval2, offset);
        size_t idx = hash % layoutLen;
        for (size_t i = 0; ; i++)
        {
            auto j = flattenedLayout.find(idx + i);
            if (j == flattenedLayout.end())
            {
                fprintf(stderr,
                    "\33[31mLOST ENTRY\33[0m (hash=%.16lX, idx=%zu, at=%zu)\n",
                    hash, idx, idx + i);
                lEntry.type->dump();
                abort();
            }
            if (j->second == &lEntry)
                break;
        }
    }
#endif

    // Step (3): build the LLVM representation of the array:
    llvm::LLVMContext &Cxt = M.getContext();
    std::vector<llvm::Constant *> Entries;
    bool done = false;
    for (size_t i = 0; !done; i++)
    {
        auto j = flattenedLayout.find(i);
        if (j == flattenedLayout.end())
        {
            Entries.push_back(EmptyEntry);
            done = (i >= layoutLen);
            continue;
        }
        const LayoutEntry &lEntry = *j->second;

        std::vector<llvm::Constant *> Elems;
        Elems.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt),
            lEntry.finalHash));
        Elems.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt),
            0));
        Elems.push_back(llvm::ConstantVector::get({
            llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt), lEntry.lb),
            llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt), lEntry.ub)}));
        llvm::Constant *Entry = llvm::ConstantStruct::get(EntryTy, Elems);

        Entries.push_back(Entry);
    }

    llvm::ArrayType *LayoutTy = llvm::ArrayType::get(EntryTy, Entries.size());
    llvm::Constant *Layout = llvm::ConstantArray::get(LayoutTy, Entries);

    return std::make_pair(Layout, Entries.size());
}

/*
 * Build a suitable name for a "composite" type, e.g., structs, classes, etc.
 * Normally, this is just the struct "tag" (i.e., the name).  This function
 * can also demangle C++ names.  For "anonymous" structs, this function can
 * build a unique name based on the type's layout.
 */
static void buildCompositeTypeName(llvm::DICompositeType *CompositeTy,
    std::string &name, TypeInfo &tInfo, bool demangle = false,
    bool ignoreAnon = false)
{
    bool isCpp = false;
    llvm::StringRef Ident = CompositeTy->getIdentifier();
    if (Ident.size() >= 4 && Ident[0] == '_' && Ident[1] == 'Z' &&
            Ident[2] == 'T' && Ident[3] == 'S')
        isCpp = true;
    llvm::StringRef Name = CompositeTy->getName();

    if (isAnonymousType(CompositeTy))
    {
        if (ignoreAnon)
            return;

        // For anonymous types we generate a name based on the layout, i.e.:
        // <anon HASH>
        HashContext cxt;
        update(cxt, LAYOUT_TAG, sizeof(LAYOUT_TAG)-1);

        llvm::DINodeArray Elements = CompositeTy->getElements();
        for (auto Element: Elements)
        {
            if (llvm::isa<llvm::DISubprogram>(Element) ||
                llvm::isa<llvm::DIEnumerator>(Element))
                continue;   // Skip methods, etc.
            auto Ty = llvm::dyn_cast<llvm::DIType>(Element);
            if (Ty == nullptr)
                continue;
            size_t offset = 0;
            bool isStatic = false, isBitField = false, isInheritance = false,
                 isVirtual = false;
            Ty = getMemberType(Ty, offset, isStatic, isBitField, isInheritance,
                isVirtual);
            if (Ty == nullptr || isStatic || isVirtual)
                continue;

            HashVal hashType = buildTypeHash(Ty, tInfo);
            offset = offset / CHAR_BIT;
            hashType.i64[0] ^= offset;

            update(cxt, (char *)hashType.i8, sizeof(hashType.i8));
        }

        HashVal val = final(cxt);
        char buf[100];
        snprintf(buf, sizeof(buf)-1,
            "<anon %.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X"
                  "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X>",
            (uint32_t)val.i8[0],  (uint32_t)val.i8[1],  (uint32_t)val.i8[2],
            (uint32_t)val.i8[3],  (uint32_t)val.i8[4],  (uint32_t)val.i8[5],
            (uint32_t)val.i8[6],  (uint32_t)val.i8[7],  (uint32_t)val.i8[8],
            (uint32_t)val.i8[9],  (uint32_t)val.i8[10], (uint32_t)val.i8[11],
            (uint32_t)val.i8[12], (uint32_t)val.i8[13], (uint32_t)val.i8[14],
            (uint32_t)val.i8[15]);
        name += buf;
        return;
    }

    if (isCpp)
    {
        if (!demangle)
        {
            name += Ident;
            return;
        }

        // For C++ types we reconstruct the name from the mangled identifier.
        std::string mangledName("_Z");
        mangledName.append(Ident.str(), 4, std::string::npos);
        int status = 0;
        char* res = abi::__cxa_demangle(mangledName.c_str(), NULL, NULL,
            &status);
        if (status != 0)
        {
            // Fallback: just use the mangled name:
            name += Ident;
            return;
        }
        name += res;
        free(res);
        return;
    }

    name += Name.str();
}

/*
 * Build a typename suitable for humans.
 */
static void buildTypeHumanName(llvm::DIType *Ty, std::string &humanName,
    TypeInfo &tInfo)
{
    Ty = normalizeType(Ty);

    auto i = tInfo.names.find(Ty);
    if (i != tInfo.names.end())
    {
        humanName += i->second;
        return;
    }
    auto j = tInfo.names.insert(std::make_pair(Ty, ""));
    std::string &name = j.first->second;

    if (Ty == nullptr)
        name += "int8_t";
    else if (isVPtrType(Ty))
    {
        auto *DerivedTy = llvm::dyn_cast<llvm::DIDerivedType>(Ty);
        std::string tempName(DerivedTy->getName().str());
        tempName.erase(0, 6);   // strlen("_vptr$") == 6
        name += "<vptr ";
        name += tempName;
        name += '>';
    }
    else if (auto *BasicTy = llvm::dyn_cast<llvm::DIBasicType>(Ty))
    {
        switch (BasicTy->getEncoding())
        {
        case llvm::dwarf::DW_ATE_signed_char:
        case llvm::dwarf::DW_ATE_unsigned_char:
        case llvm::dwarf::DW_ATE_boolean:
            name += "int8_t";
            break;
        case llvm::dwarf::DW_ATE_signed:
        case llvm::dwarf::DW_ATE_unsigned:
        case llvm::dwarf::DW_ATE_UTF:
            name += "int";
            name += std::to_string(BasicTy->getSizeInBits());
            name += "_t";
            break;
        case llvm::dwarf::DW_ATE_float:
            name += "float";
            name += std::to_string(BasicTy->getSizeInBits());
            name += "_t";
            break;
        case llvm::dwarf::DW_ATE_complex_float:
            name += "complex float";
            name += std::to_string(BasicTy->getSizeInBits() / 2);
            name += "_t";
            break;
        case 128:
            name += "complex int";
            name += std::to_string(BasicTy->getSizeInBits() / 2);
            name += "_t";
            break;
        default:
            EFFECTIVE_DEBUG_PRINT("buildTypeHumanName: unknown basic\n");
            name += "<unknown basic>";
            return;
        }
    }
    else if (auto *DerivedTy = llvm::dyn_cast<llvm::DIDerivedType>(Ty))
    {
        buildTypeHumanName(DerivedTy->getBaseType().resolve(), name, tInfo);
        switch (DerivedTy->getTag())
        {
        case llvm::dwarf::DW_TAG_pointer_type:
        case llvm::dwarf::DW_TAG_reference_type:
        case llvm::dwarf::DW_TAG_rvalue_reference_type:
            name += " *";
            break;
        default:
            name += "<unknown derived>";
            break;
        }
    }
    else if (auto *CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty))
    {
        switch (CompositeTy->getTag())
        {
        case llvm::dwarf::DW_TAG_structure_type:
            if (isNewArrayType(Ty))
                break;
            name += "struct ";
            break;
        case llvm::dwarf::DW_TAG_class_type:
            name += "class ";
            break;
        case llvm::dwarf::DW_TAG_union_type:
            name += "union ";
            break;
        case llvm::dwarf::DW_TAG_enumeration_type:
            name += "enum ";
            break;
        default:
            name += "<unknown composite> ";
            break;
        }
        buildCompositeTypeName(CompositeTy, name, tInfo,
            /*demangle=*/true, /*ignoreAnon=*/true);
    }
    else if (auto *FuncTy = llvm::dyn_cast<llvm::DISubroutineType>(Ty))
    {
        llvm::DITypeRefArray Types = FuncTy->getTypeArray();
        llvm::DIType *RetTy = Types[0].resolve();
        buildTypeHumanName(RetTy, name, tInfo);
        name += " (*)(";
        unsigned argNum = 0;
        for (auto Arg: Types)
        {
            switch (argNum)
            {
            case 0:
                argNum++;
                continue;
            case 1:
                break;
            default:
                name += ", ";
                break;
            }
            llvm::DIType *ArgTy = Arg.resolve();
            buildTypeHumanName(ArgTy, name, tInfo);
            argNum++;
        }
        name += ")";
    }
    else
        name += "<unknown type>";

    humanName += name;
}

/*
 * Comparison function for type info entry sorting.
 */
static bool infoEntryCompare(llvm::Constant *Entry1, llvm::Constant *Entry2)
{
    auto *SEntry1 = llvm::dyn_cast<llvm::ConstantStruct>(Entry1);
    auto *SEntry2 = llvm::dyn_cast<llvm::ConstantStruct>(Entry2);
    if (SEntry1 == nullptr || SEntry2 == nullptr)
        return (Entry1 < Entry2);
    auto *Elem1 = SEntry1->getOperand(2);
    auto *Elem2 = SEntry2->getOperand(2);
    if (Elem1 == nullptr || Elem2 == nullptr)
        return (Entry1 < Entry2);
    auto *LB1 = llvm::dyn_cast<llvm::ConstantInt>(Elem1);
    auto *LB2 = llvm::dyn_cast<llvm::ConstantInt>(Elem2);
    if (LB1 == nullptr || LB2 == nullptr)
        return (Entry1 < Entry2);
    return (LB1->getZExtValue() < LB2->getZExtValue());
}

/*
 * Build the type meta data for human readable error messages (i.e., the
 * EFFECTIVE_INFO metadata).
 */
static llvm::Constant *buildTypeInfo(llvm::Module &M, llvm::DIType *Ty,
    size_t size, const FAM &fam, bool incomplete, TypeInfo &tInfo)
{
    Ty = normalizeType(Ty);

    auto i = tInfo.infos.find(Ty);
    if (i != tInfo.infos.end())
        return i->second;

    if (Ty == nullptr)
    {
        llvm::Constant *Info = M.getOrInsertGlobal(TYPE_INFO_PREFIX "INT8",
            InfoTy);
        tInfo.infos.insert(std::make_pair(Ty, Info));
        return Info;
    }
    else if (auto *BasicTy = llvm::dyn_cast<llvm::DIBasicType>(Ty))
    {
        std::string name(TYPE_INFO_PREFIX);
        bool ok = true;
        switch (BasicTy->getEncoding())
        {
        case llvm::dwarf::DW_ATE_signed_char:
        case llvm::dwarf::DW_ATE_unsigned_char:
        case llvm::dwarf::DW_ATE_boolean:
            name += "INT8";
            break;
        case llvm::dwarf::DW_ATE_signed:
        case llvm::dwarf::DW_ATE_unsigned:
        case llvm::dwarf::DW_ATE_UTF:
            name += "INT";
            name += std::to_string(BasicTy->getSizeInBits());
            break;
        case llvm::dwarf::DW_ATE_float:
            name += "FLOAT";
            name += std::to_string(BasicTy->getSizeInBits());
            break;
        default:
            ok = false;
            break;
        }
        if (ok)
        {
            llvm::Constant *Info = M.getOrInsertGlobal(name, InfoTy);
            tInfo.infos.insert(std::make_pair(Ty, Info));
            return Info;
        }
    }

    int flags = 0;
    if (auto *CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty))
        flags |= (CompositeTy->getTag() == llvm::dwarf::DW_TAG_union_type?
                  EFFECTIVE_INFO_FLAG_UNION: 0);
    if (fam.type != nullptr)
        flags |= EFFECTIVE_INFO_FLAG_FLEXIBLE_LEN;
    if (incomplete)
        flags |= EFFECTIVE_INFO_FLAG_INCOMPLETE;

    HashVal hash = buildTypeHash(Ty, tInfo);
    std::stringstream infoName;
    infoName << TYPE_INFO_PREFIX;
    infoName << std::hex << hash.i64[1] << hash.i64[0];
    if (auto *InfoGV = M.getGlobalVariable(infoName.str()))
    {
        llvm::Constant *Info = llvm::ConstantExpr::getBitCast(InfoGV,
            InfoTy->getPointerTo());
        tInfo.infos.insert(std::make_pair(Ty, Info));
        return Info;
    }

    std::string humanName;
    buildTypeHumanName(Ty, humanName, tInfo);
    llvm::LLVMContext &Cxt = M.getContext();
    llvm::Constant *NameInit = llvm::ConstantDataArray::getString(Cxt,
        humanName);
    llvm::GlobalVariable *NameGV = new llvm::GlobalVariable(M,
        NameInit->getType(), true, llvm::GlobalValue::PrivateLinkage,
        NameInit, "EFFECTIVE_STRING");
    NameGV->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
    llvm::Constant *Name = llvm::ConstantExpr::getPointerCast(NameGV,
        llvm::Type::getInt8PtrTy(Cxt));

    std::vector<llvm::Constant *> Entries;
    if (auto *CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty))
    {
        llvm::DINodeArray Elements = CompositeTy->getElements();
        std::map<size_t, llvm::DIType *> Bitfields;
        for (auto Element: Elements)
        {
            auto *Ty = llvm::dyn_cast<llvm::DIType>(Element);
            if (Ty == nullptr)
                continue;
            size_t offset = 0;
            bool isStatic = false, isBitField = false, isInheritance = false,
                 isVirtual = false;
            Ty = getMemberType(Ty, offset, isStatic, isBitField, isInheritance,
                isVirtual);
            if (Ty == nullptr || isStatic)
                continue;
            if (offset == fam.offset && Ty == fam.type)
                continue;
            if (isBitField)
            {
                auto i = Bitfields.find(offset);
                if (i != Bitfields.end() && i->second == Ty)
                    continue;       // Duplicate
                Bitfields.insert(std::make_pair(offset, Ty));
            }

            size_t arrayLen = 1;
            auto *CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty);
            if (CompositeTy != nullptr &&
                CompositeTy->getTag() == llvm::dwarf::DW_TAG_array_type)
            {
                llvm::DIType *ElemTy = CompositeTy->getBaseType().resolve();
                ElemTy = normalizeType(ElemTy);
                arrayLen = Ty->getSizeInBits() / ElemTy->getSizeInBits();
            }
            Ty = normalizeType(Ty);
            offset = offset / CHAR_BIT;
            size_t size = Ty->getSizeInBits() / CHAR_BIT;
            size_t lb = offset, ub = offset + arrayLen * size;
            uint32_t flags = 0;
            if (isInheritance)
                flags |= EFFECTIVE_INFO_ENTRY_FLAG_INHERITANCE;
            if (isVirtual)
                flags |= EFFECTIVE_INFO_ENTRY_FLAG_VIRTUAL;
            FAM NONE = {nullptr, SIZE_MAX};
            llvm::Constant *Next = buildTypeInfo(M, Ty, size, NONE, false,
                tInfo);
            llvm::Constant *Flags = llvm::ConstantInt::get(
                llvm::Type::getInt32Ty(Cxt), flags);
            llvm::Constant *LB = llvm::ConstantInt::get(
                llvm::Type::getInt64Ty(Cxt), lb);
            llvm::Constant *UB = llvm::ConstantInt::get(
                llvm::Type::getInt64Ty(Cxt), ub);
            llvm::Constant *Entry = llvm::ConstantStruct::get(
                InfoEntryTy, {Next, Flags, LB, UB});
            Entries.push_back(Entry);
        }
    }
    std::sort(Entries.begin(), Entries.end(), infoEntryCompare);

    llvm::StructType *InfoTy1 = makeTypeInfoType(M, Entries.size());
    llvm::GlobalVariable *InfoGV = new llvm::GlobalVariable(M, InfoTy1, true,
        llvm::GlobalValue::WeakAnyLinkage, 0, infoName.str());
    llvm::Constant *Size =
        llvm::ConstantInt::get(llvm::Type::getInt32Ty(Cxt), size);
    llvm::Constant *NumEntries =
        llvm::ConstantInt::get(llvm::Type::getInt32Ty(Cxt), Entries.size());
    llvm::Constant *Flags = 
        llvm::ConstantInt::get(llvm::Type::getInt32Ty(Cxt), flags);
    llvm::Constant *Next = nullptr;
    if (fam.type == nullptr)
        Next = llvm::ConstantPointerNull::get(InfoTy->getPointerTo());
    else
    {
        auto *Ty = fam.type;
        size_t size = Ty->getSizeInBits() / CHAR_BIT;
        FAM NONE = {nullptr, SIZE_MAX};
        Next = buildTypeInfo(M, Ty, size, NONE, false, tInfo);
    }
    llvm::ArrayType *EntriesTy = llvm::ArrayType::get(InfoEntryTy,
        Entries.size());
    llvm::Constant *Entries1 = llvm::ConstantArray::get(EntriesTy, Entries);
    llvm::Constant *InfoInit = llvm::ConstantStruct::get(InfoTy1, 
        {Name, Size, NumEntries, Flags, Next, Entries1});
    InfoGV->setInitializer(InfoInit);
    llvm::Constant *Info = llvm::ConstantExpr::getBitCast(InfoGV,
        InfoTy->getPointerTo());
    
    tInfo.infos.insert(std::make_pair(Ty, Info));
    return Info;
}

/*
 * Build a hash value for type `Ty'.
 */
static HashVal buildTypeHash(llvm::DIType *Ty, TypeInfo &tInfo)
{
    Ty = normalizeType(Ty);

    auto i = tInfo.hashes.find(Ty);
    if (i != tInfo.hashes.end())
        return i->second;
    HashVal zero;
    memset(&zero, 0, sizeof(zero));
    auto j = tInfo.hashes.insert(std::make_pair(Ty, zero));
    HashVal &hash = j.first->second;

    if (Ty == nullptr)
        hash = hashString(BASIC_TYPE_TAG, "int8_t");
    else if (isVPtrType(Ty))
    {
        std::string name;
        buildTypeHumanName(Ty, name, tInfo);
        hash = hashString(VPTR_TYPE_TAG, name.c_str());
    }
    else if (llvm::isa<llvm::DIBasicType>(Ty))
    {
        std::string name;
        buildTypeHumanName(Ty, name, tInfo);
        hash = hashString(BASIC_TYPE_TAG, name.c_str());
    }
    else if (auto *DerivedTy = llvm::dyn_cast<llvm::DIDerivedType>(Ty))
    {
        HashVal hash0 = buildTypeHash(DerivedTy->getBaseType().resolve(),
            tInfo);
        switch (DerivedTy->getTag())
        {
        case llvm::dwarf::DW_TAG_pointer_type:
        case llvm::dwarf::DW_TAG_reference_type:
        case llvm::dwarf::DW_TAG_rvalue_reference_type:
            hash = hashHash(POINTER_TYPE_TAG, hash0);
            break;
        default:
            EFFECTIVE_FATAL_ERROR("unknown derived type");
        }
    }
    else if (auto *CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty))
    {
        const char *prefix = nullptr;
        switch (CompositeTy->getTag())
        {
        case llvm::dwarf::DW_TAG_enumeration_type:
            prefix = ENUM_TYPE_TAG; break;
        case llvm::dwarf::DW_TAG_structure_type:
            prefix = STRUCT_TYPE_TAG; break;
        case llvm::dwarf::DW_TAG_class_type:
            prefix = CLASS_TYPE_TAG; break;
        case llvm::dwarf::DW_TAG_union_type:
            prefix = UNION_TYPE_TAG; break;
        default:
            EFFECTIVE_FATAL_ERROR("unknown composite type");
        }
        std::string tagName;
        buildCompositeTypeName(CompositeTy, tagName, tInfo,
            /*demangle=*/false);
        hash = hashString(prefix, tagName.c_str());
    }
    else if (auto *FuncTy = llvm::dyn_cast<llvm::DISubroutineType>(Ty))
    {
        std::string name;
        buildTypeHumanName(Ty, name, tInfo);
        hash = hashString(FUNCTION_TYPE_TAG, name.c_str());
    }
    else
        EFFECTIVE_FATAL_ERROR("unknown type");

    return hash;
}

/*
 * A simple test to see if the given type is (likely) a struct with a
 * flexible array member (FAM), e.g. struct vector { int len; int data[]; }
 */
static FAM getFlexibleArrayMember(llvm::DIType *Ty, size_t baseOffset = 0)
{
    const FAM NONE = {nullptr, SIZE_MAX};

    auto *CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty);
    if (CompositeTy == nullptr)
        return NONE;
    if (CompositeTy->getTag() != llvm::dwarf::DW_TAG_structure_type)
    {
        // C++ does not allow flexible length elements, so no classes.
        return NONE;
    }
    llvm::DINodeArray Elements = CompositeTy->getElements();
    if (Elements.size() == 0)
        return NONE;        // Empty struct.
    llvm::DIType *LastElem = nullptr;
    ssize_t lastOffset = -1;
    for (auto Element: Elements)
    {
        auto *Ty = llvm::dyn_cast<llvm::DIType>(Element);
        if (Ty == nullptr)
            continue;
        size_t offset = 0;
        bool isStatic = false, isBitField = false, isInheritance = false,
             isVirtual = false;
        Ty = getMemberType(Ty, offset, isStatic, isBitField, isInheritance,
            isVirtual);
        if (Ty == nullptr || isStatic || isInheritance || isBitField ||
                isVirtual)
            continue;
        offset = offset / CHAR_BIT;
        if ((ssize_t)offset > lastOffset)
        {
            LastElem = Ty;
            lastOffset = offset;
        }
    }
    if (LastElem == nullptr)
        return NONE;

    // Analysis:
    CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(LastElem);
    if (CompositeTy == nullptr)
        return NONE;
    if (CompositeTy->getTag() == llvm::dwarf::DW_TAG_array_type)
    {
        llvm::DINodeArray Elements = CompositeTy->getElements();
        bool seen = false;
        for (auto Element: Elements)
        {
            auto *Subrange = llvm::dyn_cast<llvm::DISubrange>(Element);
            if (Subrange == nullptr)
                continue;
            if (seen)
                return NONE;
            if (Subrange->getLowerBound() != 0)
                return NONE;
            int64_t count = Subrange->getCount();
            if (count != -1 && count != 0 && count != 1)
                return NONE;
            seen = true;
        }
        return {LastElem, baseOffset + lastOffset};
    }
    return getFlexibleArrayMember(CompositeTy, baseOffset + lastOffset);
}

/*
 * This is similar to getFlexibleArrayMember(), but for llvm types.  This is
 * necessary for bounds narrowing where we do not have debug type information.
 * It is assumed that the debug and llvm types correspond.
 */
static bool isFlexibleArrayMember(llvm::StructType *StructTy,
    unsigned elemIdx)
{
    if (StructTy->getNumElements()-1 != elemIdx)
        return false;
    llvm::Type *Ty = StructTy->getElementType(elemIdx);
    auto *ArrayTy = llvm::dyn_cast<llvm::ArrayType>(Ty);
    if (ArrayTy == nullptr)
        return false;
    size_t numElems = ArrayTy->getNumElements();
    return (numElems == 0 || numElems == 1);
}

/*
 * Compile the type into the EffectiveSan metadata representation for type
 * checking (i.e., the EFFECTIVE_TYPE metadata).
 */
static const TypeEntry &compileType(llvm::Module &M, llvm::DIType *Ty,
    TypeInfo &tInfo, unsigned multiplier = 1)
{
    Ty = normalizeType(Ty);

    auto i = tInfo.cache.find(Ty);
    if (i != tInfo.cache.end())
        return i->second;

    auto *DerivedTy = llvm::dyn_cast<llvm::DIDerivedType>(Ty);
    auto *CompositeTy = llvm::dyn_cast<llvm::DICompositeType>(Ty);
    auto *FuncTy = llvm::dyn_cast<llvm::DISubroutineType>(Ty);
    auto *BasicTy = llvm::dyn_cast<llvm::DIBasicType>(Ty);

    std::string humanName;
    buildTypeHumanName(Ty, humanName, tInfo);
    if (isBlacklisted("type", humanName))
    {
        const TypeEntry &charEntry = compileType(M, nullptr, tInfo);
        tInfo.cache.insert(std::make_pair(Ty, charEntry));
        return charEntry;
    }
    HashVal hash = buildTypeHash(Ty, tInfo);
    LayoutInfo layout;
    size_t layoutLen = 2;
    bool incomplete = false;
    FAM fam = {nullptr, SIZE_MAX};
    std::stringstream metaName;
    metaName << TYPE_META_PREFIX;
    bool isInt8 = false;
    if (BasicTy != nullptr)
    {
        switch (BasicTy->getEncoding())
        {
        case llvm::dwarf::DW_ATE_signed_char:
        case llvm::dwarf::DW_ATE_unsigned_char:
        case llvm::dwarf::DW_ATE_boolean:
            metaName << "INT8";
            isInt8 = true;
            break;
        case llvm::dwarf::DW_ATE_signed:
        case llvm::dwarf::DW_ATE_unsigned:
        case llvm::dwarf::DW_ATE_UTF:
            metaName << "INT";
            metaName << std::to_string(BasicTy->getSizeInBits());
            break;
        case llvm::dwarf::DW_ATE_float:
            metaName << "FLOAT";
            metaName << std::to_string(BasicTy->getSizeInBits());
            break;
        default:
            metaName << std::hex << hash.i64[1] << hash.i64[0];
        }
    }
    else
        metaName << std::hex << hash.i64[1] << hash.i64[0];
    TypeEntry &entry = addTypeEntry(tInfo, Ty, humanName, hash, nullptr,
        isInt8);
    if (auto *MetaGV = M.getGlobalVariable(metaName.str()))
    {
        // This can happen when the same type has multiple DI entries,
        // e.g. anonymous types defined multiple times at different locations.
        llvm::Constant *Meta = llvm::ConstantExpr::getBitCast(MetaGV,
            TypeTy->getPointerTo());
        entry.typeMeta = Meta;
        return entry;
    }

    if (Ty->isForwardDecl())
    {
        // This should not happen; so warn the user.
        std::string msg("type (");
        msg += humanName;
        msg += ") is a forward declaration; type metadata will be incomplete";
        warning(M, msg);
    }
 
    // By default, any type can be coerced into (char[]).
    llvm::LLVMContext &Cxt = M.getContext();
    llvm::Constant *Next = llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt),
        EFFECTIVE_TYPE_INT8_HASH);

    // An object of type T[] is always an object of type T[]:
    addLayoutEntry(layout, tInfo, 0, Ty, -EFFECTIVE_DELTA, EFFECTIVE_DELTA,
        true);

    if (isVPtrType(Ty))
    {
        // Virtual Function Table pointer.  Can be coerced into (void *):
        const TypeEntry &voidPtrEntry = compileType(M, Int8PtrTy, tInfo);
        tInfo.cache.erase(Ty);
        tInfo.cache.insert(std::make_pair(Ty, voidPtrEntry));
        return voidPtrEntry;
    }
    else if (Ty == Int8PtrTy)
    {
        Next = llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt),
            EFFECTIVE_COERCED_INT8_PTR_HASH);
    }
    else if (DerivedTy != nullptr &&
        (DerivedTy->getTag() == llvm::dwarf::DW_TAG_pointer_type ||
         DerivedTy->getTag() == llvm::dwarf::DW_TAG_reference_type ||
         DerivedTy->getTag() == llvm::dwarf::DW_TAG_rvalue_reference_type))
    {
        // Pointer type (T *)
        // All pointers can be coerced into (void *):
        Next = llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt),
            EFFECTIVE_TYPE_INT8_PTR_HASH);
    }
    else if (CompositeTy != nullptr &&
             CompositeTy->getTag() == llvm::dwarf::DW_TAG_enumeration_type)
    {
        // Enum type.
        // All enums can be coerced to (int):
        const TypeEntry &intEntry = compileType(M, Int32Ty, tInfo);
        tInfo.cache.erase(Ty);
        tInfo.cache.insert(std::make_pair(Ty, intEntry));
        return intEntry;

    }
    else if (CompositeTy != nullptr &&
             (CompositeTy->getTag() == llvm::dwarf::DW_TAG_structure_type ||
              CompositeTy->getTag() == llvm::dwarf::DW_TAG_class_type ||
              CompositeTy->getTag() == llvm::dwarf::DW_TAG_union_type))
    {
        // Struct or class type
        fam = getFlexibleArrayMember(CompositeTy);
#ifdef EFFECTIVE_LAYOUT_DEBUG
        fprintf(stderr, "%s:\n", humanName.c_str());
#endif
        buildLayout(CompositeTy, 0, fam, tInfo, layout);
#ifdef EFFECTIVE_LAYOUT_DEBUG
        fprintf(stderr, "\n");
#endif

        // Check if layout has too many entries:
        if (layout.size() > option_max_sub_objs)
        {
            std::string msg("type (");
            msg += humanName;
            msg += ") has too many sub-objects (got ";
            msg += std::to_string(layout.size());
            msg += ", but limit is ";
            msg += std::to_string(option_max_sub_objs);
            msg += "); ";
            if (shrinkLayoutToFit(layout, option_max_sub_objs))
            {
                incomplete = true;
                msg += "type meta data will be incomplete";
                warning(M, msg);
            }
            else
            {
                msg += "type will be treated as (char[])";
                warning(M, msg);

                const TypeEntry &charEntry = compileType(M, nullptr, tInfo);
                tInfo.cache.erase(Ty);
                tInfo.cache.insert(std::make_pair(Ty, charEntry));
                return charEntry;
            }
        }

        layoutLen = getLayoutLength(layout);
        layoutLen *= multiplier;
    }
    else if (FuncTy != nullptr || BasicTy != nullptr)
    {
        // NOP
    }
    else
        EFFECTIVE_FATAL_ERROR("unknown type");

    size_t size = 0, size_fam = 0, offset_fam = 0;
    if (fam.type != nullptr)
    {
        auto *Ty = getArrayElementType(fam.type);
        Ty = normalizeType(Ty);
        size = fam.offset;
        size_fam = getSizeOfType(Ty);
        offset_fam = size;
    }
    else
    {
        size = getSizeOfType(Ty);
        size = (size == 0? 1: size);
        size_fam = size;
    }
    size_t magic = EFFECTIVE_MAGIC(size_fam);
    size_t hval = getTypeHash(Ty, entry.hash);
    uint64_t mask = layoutLen-1;
    llvm::Constant *Info = buildTypeInfo(M, Ty, size, fam, incomplete, tInfo);
    llvm::Constant *Layout = nullptr;
    uint64_t hval2 = hval;
    size_t finalLen;

    // Build the layout hash table.
    for (unsigned i = 0; ; i++)
    {
        auto Result = compileLayout(M, hval2, layoutLen, layout);
        Layout = Result.first;
        finalLen = Result.second;
        if (Layout != nullptr)
            break;
        if (i >= 64)
        {
            // We have attempted to build the layout many times, but there
            // are too many collisions.  As a last resort, try doubling the
            // size of the layout hash table.
            EFFECTIVE_DEBUG_PRINT("warning: failed to build layout hash "
                "table; trying larger size [%zu -> %zu]\n", layoutLen,
                2 * layoutLen);
            tInfo.cache.erase(Ty);
            multiplier *= 2;
            return compileType(M, Ty, tInfo, multiplier);
        }
        hval2 = getNextLayoutHash(hash, i, hval2, layoutLen);
    }

    llvm::StructType *MetaTy = makeTypeMetaType(M, finalLen);
    llvm::GlobalVariable *MetaGV = new llvm::GlobalVariable(M, MetaTy, true,
        llvm::GlobalValue::WeakAnyLinkage, 0, metaName.str());
    llvm::Constant *Meta = llvm::ConstantExpr::getBitCast(MetaGV,
        TypeTy->getPointerTo());
    entry.typeMeta = Meta;

    std::vector<llvm::Constant *> Elems;
    Elems.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt),
        hval));
    Elems.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt),
        hval2));
    Elems.push_back(llvm::ConstantInt::get(llvm::Type::getInt32Ty(Cxt),
        size));
    Elems.push_back(llvm::ConstantInt::get(llvm::Type::getInt32Ty(Cxt),
        size_fam));
    Elems.push_back(llvm::ConstantInt::get(llvm::Type::getInt32Ty(Cxt),
        offset_fam));
    Elems.push_back(llvm::ConstantInt::get(llvm::Type::getInt32Ty(Cxt),
        EFFECTIVE_SANITY));
    Elems.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt),
        magic));
    Elems.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt),
        mask));
    Elems.push_back(Info);
    Elems.push_back(Next);
    Elems.push_back(Layout);
    llvm::Constant *MetaInit = llvm::ConstantStruct::get(MetaTy, Elems);
    MetaGV->setInitializer(MetaInit);

    return entry;
}

/*****************************************************************************/
/* TYPE CHECK INSTRUMENTATION                                                */
/*****************************************************************************/

/*
 * Find the best insert point based on all users.
 */
static llvm::Instruction *findBestInsertPoint(llvm::DominatorTree &DT,
    llvm::Function &F, llvm::Value *Ptr, llvm::Instruction *IBest,
    std::set<llvm::Value *> &Seen)
{
    auto i = Seen.find(Ptr);
    if (i != Seen.end())
        return IBest;
    Seen.insert(Ptr);

    for (auto *User: Ptr->users())
    {
        if (auto *C = llvm::dyn_cast<llvm::Constant>(User))
        {
            IBest = findBestInsertPoint(DT, F, C, IBest, Seen);
            continue;
        }
        auto *I = llvm::dyn_cast<llvm::Instruction>(User);
        if (I == nullptr)
            continue;
        llvm::BasicBlock *BB = I->getParent();
        if (BB == nullptr || BB != &F.getEntryBlock())
            continue;
        if (DT.dominates(I, IBest))
            IBest = I;
    }

    return IBest;
}

/*
 * Find the best place to insert instructions *after* `Ptr' is defined.
 */
static InsertPoint nextInsertPoint(llvm::Function &F, llvm::Value *Ptr)
{
    if (auto Invoke = llvm::dyn_cast<llvm::InvokeInst>(Ptr))
    {
        // This is a tricky case since we an invoke instruction is also a
        // terminator.  Instead we create a new BasicBlock to insert into.
        llvm::BasicBlock *fromBB = Invoke->getParent();
        llvm::BasicBlock *toBB = Invoke->getNormalDest();
        llvm::BasicBlock *newBB = SplitEdge(fromBB, toBB);
        InsertPoint IP = {newBB, newBB->begin()};
        return IP;
    }
    else if (llvm::isa<llvm::Argument>(Ptr) ||
             llvm::isa<llvm::Constant>(Ptr))
    {
        // For arguments/globals we insert into the entry basic block.
        llvm::DominatorTree DT(F);
        std::set<llvm::Value *> Seen;
        llvm::Instruction *IBest = F.getEntryBlock().getTerminator();
        IBest = findBestInsertPoint(DT, F, Ptr, IBest, Seen);
        llvm::BasicBlock::iterator i(IBest);
        InsertPoint IP = {IBest->getParent(), i};
        return IP;
    }
    else if (llvm::isa<llvm::Instruction>(Ptr) &&
            !llvm::isa<llvm::TerminatorInst>(Ptr))
    {
        llvm::Instruction *I = llvm::dyn_cast<llvm::Instruction>(Ptr);
        assert(I != nullptr);
        llvm::BasicBlock::iterator i(I);
        i++;
        llvm::BasicBlock *BB = I->getParent();
        InsertPoint IP = {BB, i};
        return IP;
    }
    else
        EFFECTIVE_FATAL_ERROR("failed to create insert point");
}

static llvm::DIType *getPointeeType(llvm::DIType *Ty)
{
    while (true)
    {
        auto *DerivedTy = llvm::dyn_cast<llvm::DIDerivedType>(Ty);
        if (DerivedTy == nullptr)
            return nullptr;
        switch (DerivedTy->getTag())
        {
        case llvm::dwarf::DW_TAG_typedef:
            Ty = DerivedTy->getBaseType().resolve();
            continue;
        case llvm::dwarf::DW_TAG_pointer_type:
        case llvm::dwarf::DW_TAG_reference_type:
        case llvm::dwarf::DW_TAG_rvalue_reference_type:
            return DerivedTy->getBaseType().resolve();
        default:
            return nullptr;
        }
    }
}

static std::string showValue(llvm::Value *Val)
{
    std::string str;
    llvm::raw_string_ostream stream(str);
    Val->print(stream);
    return str;
}

/*
 * Get the "effectiveSan" type annotation or return nullptr if it does not
 * exist.
 */
static llvm::DIType *getDeclaredTypeAnnotation(llvm::Value *Ptr)
{
    llvm::DIType *Ty = llvm::getEffectiveSanType(Ptr);
    if (Ty == nullptr)
    {
        // Attempt to infer type instead.  This can help when the optimizer
        // removes some annotations.  It is easier just to infer here.
        llvm::Type *Ty = Ptr->getType();
        if (auto *PTy = llvm::dyn_cast<llvm::PointerType>(Ty))
            Ty = PTy->getElementType();
        if (Ty->isIntegerTy(8))
            return Int8Ty;
        if (Ty->isIntegerTy(16))
            return Int16Ty;
        if (Ty->isIntegerTy(32))
            return Int32Ty;
        if (Ty->isIntegerTy(64))
            return Int64Ty;
        if (Ty->isIntegerTy(128))
            return Int128Ty;
        return nullptr;
    }
    Ty = getPointeeType(Ty);
    if (Ty == nullptr)
        return Int8Ty;
    return Ty;
}

/*
 * Get the new[] wrapper type if necessary.  It is of the form:
 *      struct <new Obj[]> { size_t cookie; Obj objs[]; }
 * where `cookie' stores the number of objects in `objs'.
 */
static llvm::DIType *getNewArrayType(llvm::Module &M, llvm::DIType *Ty,
    size_t cookieSize, TypeInfo &tInfo)
{
    if (cookieSize == 0)
        return Ty;

    llvm::DIBuilder builder(M);
    llvm::DIScope *Scope = Ty->getScope().resolve();
    llvm::DIFile *File = Ty->getFile();
    unsigned Line = Ty->getLine();
    std::string name("new ");
    buildTypeHumanName(Ty, name, tInfo);
    name += "[]";
    llvm::DIType *CookieTy = builder.createBasicType("unsigned long",
        sizeof(size_t) * CHAR_BIT, llvm::dwarf::DW_ATE_unsigned);
    CookieTy = builder.createMemberType(Scope, "cookie", File, Line,
        CookieTy->getSizeInBits(), 0, 0, llvm::DINode::FlagPublic,
        CookieTy);
    llvm::DISubrange *Subrange = builder.getOrCreateSubrange(0, -1);
    llvm::DINodeArray Subscripts = builder.getOrCreateArray({Subrange});
    llvm::DIType *DataTy = builder.createArrayType(0, 0, Ty, Subscripts);
    Ty = builder.createMemberType(Scope, "data", File, Line,
        DataTy->getSizeInBits(), DataTy->getSizeInBits(),
        cookieSize * CHAR_BIT, llvm::DINode::FlagPublic, DataTy);
    llvm::DINodeArray Elements = builder.getOrCreateArray({CookieTy, Ty});
    size_t size = cookieSize + getSizeOfType(Ty);
    Ty = builder.createStructType(Scope, name, File, Line, size * CHAR_BIT,
        0, llvm::DINode::DIFlags(), nullptr, Elements);

    return Ty;
}

/*
 * Get (generate) the type meta data for the given pointer.  If the type is
 * (char []) then this function returns NULL.  This function relies on
 * meta data inserted by the front-end.
 */
static llvm::Constant *getDeclaredType(llvm::Module &M, llvm::Value *Ptr,
    TypeInfo &tInfo, llvm::DIType **TyPtr = nullptr, bool alloc = false)
{
    llvm::DIType *Ty = getDeclaredTypeAnnotation(Ptr);
    if (Ty == nullptr)
    {
        // This occurs when the frontend has failed to annotate the type.
        // The front-end isn't perfect, so printing a message helps find new
        // holes to plug...
        std::string msg("missing type metadata for value (");
        msg += showValue(Ptr);
        msg += "); type will be treated as (char[])";
        warning(M, msg);
        return nullptr;
    }

    // Handle special wrappers for allocations:
    if (alloc)
    {
        size_t cookieSize = 0;
        if (auto *I = llvm::dyn_cast<llvm::Instruction>(Ptr))
        {
            // Check for new[] cookie.
            llvm::MDNode *Metadata = I->getMetadata("effectiveSanCookieSize");
            if (Metadata != nullptr && Metadata->getNumOperands() == 1)
            {
                llvm::Metadata *MD = Metadata->getOperand(0).get();
                if (MD != nullptr && llvm::isa<llvm::ConstantAsMetadata>(MD))
                {
                    llvm::Constant *C =
                      llvm::dyn_cast<llvm::ConstantAsMetadata>(MD)->getValue();
                    if (C != nullptr && llvm::isa<llvm::ConstantInt>(C))
                    {
                        llvm::ConstantInt *Int =
                            llvm::dyn_cast<llvm::ConstantInt>(C);
                        cookieSize = Int->getZExtValue();
                    }
                }
            }
        }

        Ty = getNewArrayType(M, Ty, cookieSize, tInfo);
    }

    if (TyPtr != nullptr)
        *TyPtr = Ty;

    const TypeEntry &entry = compileType(M, Ty, tInfo);
    return (entry.isInt8? nullptr: entry.typeMeta);
}

/*
 * Test if the cast from (SrcTy) to (DstTy) can be ignored or not.
 */
static bool canIgnoreCast(llvm::Type *SrcTy, llvm::Type *DstTy,
    llvm::Type **SubObjTyPtr = nullptr)
{
    if (DstTy->isIntegerTy(8))
    {
        // Cast from anything to (char *).  This is always allowed.
        return true;
    }
    else if (auto *StructTy = llvm::dyn_cast<llvm::StructType>(SrcTy))
    {
        // Sub-object cast: e.g. (struct {int x; } *) to (int *)
        // Selects a sub-object.
        if (StructTy->isOpaque())
            return false;
        llvm::Type *ElemTy = StructTy->getElementType(0);     // First element.
        if (SubObjTyPtr != nullptr)
            *SubObjTyPtr = ElemTy;
        if (ElemTy == DstTy)
            return true;
        return canIgnoreCast(ElemTy, DstTy, SubObjTyPtr);
    }
    else if (auto *ArrayTy = llvm::dyn_cast<llvm::ArrayType>(SrcTy))
    {
        // Array cast: e.g. (int[10] *) to (int *)
        // Does not select a sub-object.
        llvm::Type *ElemTy = ArrayTy->getElementType();
        if (ElemTy == DstTy)
            return true;
        return canIgnoreCast(ElemTy, DstTy, SubObjTyPtr);
    }
    return false;
}

/*
 * Test if the given bitcast operation can be ignored.
 */
static bool canIgnoreBitCast(llvm::BitCastInst *Cast, const CheckInfo &cInfo,
    llvm::Type **SubObjTyPtr = nullptr)
{
    if (SubObjTyPtr != nullptr)
        *SubObjTyPtr = nullptr;

    // CASE #1: Memory allocation casts:
    llvm::Value *Ptr = Cast->getOperand(0);
    auto i = cInfo.find(Ptr);
    if (i != cInfo.end() && i->second.allocType != nullptr)
    {
        // Ptr is a memory allocation.  We can ignore the cast if the
        // destination type matches the allocation type.
        const CheckEntry &Entry = i->second;
        llvm::DIType *Ty = getDeclaredTypeAnnotation(Cast);
        if (isTypeEquivalent(Ty, Entry.allocType))
            return true;
    }

    // CASE #2: Casts to sub-objects, upcasts, etc.:
    llvm::Type *SrcTy = Cast->getSrcTy(), *DstTy = Cast->getDestTy();
    SrcTy = llvm::dyn_cast<llvm::PointerType>(SrcTy)->getElementType();
    DstTy = llvm::dyn_cast<llvm::PointerType>(DstTy)->getElementType();
    if (SrcTy == nullptr || DstTy == nullptr)
        return false;
    return canIgnoreCast(SrcTy, DstTy, SubObjTyPtr);
}

/*
 * Return the pointer used by a load/store operation.
 */
static llvm::Value *getMemoryAccessPtr(llvm::Instruction &I)
{
    if (auto *Store = llvm::dyn_cast<llvm::StoreInst>(&I))
        return Store->getPointerOperand();
    else if (auto *Load = llvm::dyn_cast<llvm::LoadInst>(&I))
        return Load->getPointerOperand();
    else if (auto *Atomic = llvm::dyn_cast<llvm::AtomicRMWInst>(&I))
        return Atomic->getPointerOperand();
    else if (auto *Atomic = llvm::dyn_cast<llvm::AtomicCmpXchgInst>(&I))
        return Atomic->getPointerOperand();
    else
        return nullptr;
}

/*
 * Return `true' if `Ptr' is the result of (non-zero) pointer arithmetic.
 */
static bool isDerivedPointer(const llvm::DataLayout &DL, llvm::Value *Ptr,
    std::set<llvm::Value *> &Seen)
{
    if (auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(Ptr))
    {
        llvm::APInt Offset(64, 0);
        if (GEP->accumulateConstantOffset(DL, Offset) &&
                Offset.getSExtValue() == 0)
            return isDerivedPointer(DL, GEP->getPointerOperand(), Seen);
        return true;
    }
    if (auto *Cast = llvm::dyn_cast<llvm::BitCastInst>(Ptr))
        return isDerivedPointer(DL, Cast->getOperand(0), Seen);
    if (auto *PHI = llvm::dyn_cast<llvm::PHINode>(Ptr))
    {
        if (Seen.find(Ptr) != Seen.end())
            return false;
        Seen.insert(Ptr);
        size_t numValues = PHI->getNumIncomingValues();
        for (size_t i = 0; i < numValues; i++)
        {
            if (isDerivedPointer(DL, PHI->getIncomingValue(i), Seen))
                return true;
        }
    }
    return false;
}

/*
 * Add potential "escaping" pointer to the list.
 */
static void addEscapePtr(const llvm::DataLayout &DL, llvm::Value *Ptr,
    std::vector<llvm::Value *> &Ptrs)
{
    if (Ptr == nullptr || !Ptr->getType()->isPointerTy())
        return;
    std::set<llvm::Value *> Seen;
    if (!isDerivedPointer(DL, Ptr, Seen))
        return;
    Ptrs.push_back(Ptr);
}

/*
 * Check if this is an EffectiveSan function.
 */
static bool isEffectiveSanFunction(llvm::Function *F)
{
    if (F == nullptr || !F->hasName())
        return false;
    llvm::StringRef Name = F->getName();
    const char prefix[] = "effective_";
    if (Name.str().compare(0, sizeof(prefix)-1, prefix) == 0)
        return true;
    return false;
}

/*
 * An escaping pointer is (1) a pointer possibly derived from pointer
 * arithmetic, and (2) escapes the current function (e.g. through a reutrn,
 * call, store, etc.).  For completeness escaping pointers must be bounds
 * checked.
 */
static void getEscapePtrs(const llvm::DataLayout &DL, llvm::Instruction &I,
    std::vector<llvm::Value *> &Ptrs)
{
    if (auto *Store = llvm::dyn_cast<llvm::StoreInst>(&I))
        addEscapePtr(DL, Store->getValueOperand(), Ptrs);
    else if (auto *Ptr2Int = llvm::dyn_cast<llvm::PtrToIntInst>(&I))
        addEscapePtr(DL, Ptr2Int->getPointerOperand(), Ptrs);
    else if (llvm::isa<llvm::MemTransferInst>(&I))
        return;
    else if (llvm::isa<llvm::MemSetInst>(&I))
        return;
    else if (auto *Call = llvm::dyn_cast<llvm::CallInst>(&I))
    {
        llvm::Function *F = Call->getCalledFunction();
        if (isEffectiveSanFunction(F))
            return;
        if (F == nullptr || !F->doesNotAccessMemory())
        {
            unsigned numArgs = Call->getNumArgOperands();
            for (unsigned i = 0; i < numArgs; i++)
                addEscapePtr(DL, Call->getArgOperand(i), Ptrs);
        }
    }
    else if (auto *Invoke = llvm::dyn_cast<llvm::InvokeInst>(&I))
    {
        llvm::Function *F = Invoke->getCalledFunction();
        if (isEffectiveSanFunction(F))
            return;
        if (F == nullptr || !F->doesNotAccessMemory())
        {
            unsigned numArgs = Invoke->getNumArgOperands();
            for (unsigned i = 0; i < numArgs; i++)
                addEscapePtr(DL, Invoke->getArgOperand(i), Ptrs);
        }
    }
    else if (auto *Return = llvm::dyn_cast<llvm::ReturnInst>(&I))
        addEscapePtr(DL, Return->getReturnValue(), Ptrs);
}

/*
 * Insert a type check for `Ptr'.  The type check is inserted at a suitable
 * place after `Ptr' is created.
 */
static llvm::Value *instrumentTypeCheck(llvm::Module &M, llvm::Function &F,
    llvm::Value *Ptr, TypeInfo &tInfo, CheckInfo &cInfo, bool untyped = false)
{
    llvm::Constant *Meta = (untyped? nullptr: getDeclaredType(M, Ptr, tInfo));
    auto i = nextInsertPoint(F, Ptr);
    llvm::IRBuilder<> builder(i.bb, i.itr);
    llvm::Value *Bounds = nullptr;
    llvm::Value *Ptr1 = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());
    if (Meta == nullptr)
    {
        // If Meta==nullptr then the type is (char []).  Since this matches
        // any possible type, we simply get the object (allocation) bounds:
        llvm::Constant *BoundsGet = M.getOrInsertFunction(
            "effective_get_bounds", BoundsTy, builder.getInt8PtrTy(), nullptr);
        Bounds = builder.CreateCall(BoundsGet, {Ptr1});
    }
    else
    {
        llvm::Constant *TypeCheck = M.getOrInsertFunction(
            "effective_type_check", BoundsTy, builder.getInt8PtrTy(),
            TypeTy->getPointerTo(), nullptr);
        Bounds = builder.CreateCall(TypeCheck, {Ptr1, Meta});
    }
    CheckEntry Entry = {Bounds, nullptr, 0};
    cInfo.insert(std::make_pair(Ptr, Entry));
    return Bounds;
}

/*****************************************************************************/
/* BOUNDS CHECK INSTRUMENTATION                                              */
/*****************************************************************************/

/*
 * EffectiveSan represents bounds as a vector of 2xi64.  This might not be
 * the most efficient way of doing it, but it simplifies a lot of things.
 */

/*
 * Calculate the static bounds of a constant.  Note that this function is
 * essentially a specialized version of calculateBounds(), thus any change
 * made to the former should be made to the latter, and vice versa.
 */
static std::pair<intptr_t, intptr_t> calculateBoundsConstant(
    const llvm::DataLayout &DL, llvm::Constant *Ptr)
{
    const std::pair<intptr_t, intptr_t> EMPTY_BOUNDS = {0, 0};
    const std::pair<intptr_t, intptr_t> WIDE_BOUNDS  =
        {INTPTR_MIN, INTPTR_MAX};

    if (option_no_globals)
        return WIDE_BOUNDS;

    if (auto *CE = llvm::dyn_cast<llvm::ConstantExpr>(Ptr))
    {
        switch (CE->getOpcode())
        {
        case llvm::Instruction::GetElementPtr:
        {
            auto *GEP = llvm::dyn_cast<llvm::GEPOperator>(CE);
            llvm::Constant *Ptr =
                llvm::dyn_cast<llvm::Constant>(GEP->getPointerOperand());
            llvm::Type *Ty = Ptr->getType();
            std::pair<intptr_t, intptr_t> Bounds =
                calculateBoundsConstant(DL, Ptr);
            ssize_t lb = Bounds.first;
            ssize_t ub = Bounds.second;
            if (lb >= ub)
                return EMPTY_BOUNDS;
            int numIdxs = GEP->getNumIndices();
            for (int i = 0; i < numIdxs; i++)
            {
                llvm::Value *Idx = GEP->getOperand(i+1);
                llvm::ConstantInt *K = llvm::dyn_cast<llvm::ConstantInt>(Idx);
                if (auto *PtrTy = llvm::dyn_cast<llvm::PointerType>(Ty))
                {
                    // Pointer arithmetic.  Narrow if (possibly) OOB.
                    Ty = PtrTy->getElementType();
                    ssize_t offset = (K == nullptr? 0:
                        K->getSExtValue() * DL.getTypeAllocSize(Ty));
                    if (K == nullptr || !(lb <= offset && offset < ub))
                        return EMPTY_BOUNDS;
                    else
                    {
                        lb = (lb == INTPTR_MIN? lb: lb - offset);
                        ub = (ub == INTPTR_MAX? ub: ub - offset);
                    }
                }
                else if (auto *ArrayTy = llvm::dyn_cast<llvm::ArrayType>(Ty))
                {
                    // Array access.  Narrow if (possibly) OOB.
                    Ty = ArrayTy->getElementType();
                    ssize_t k = (K == nullptr? -1: K->getSExtValue());
                    if (k < 0 || k >= (ssize_t)ArrayTy->getNumElements())
                        return EMPTY_BOUNDS;
                    else
                    {
                        ssize_t offset = k * DL.getTypeAllocSize(Ty);
                        lb = (lb == INTPTR_MIN? lb: lb - offset);
                        ub = (ub == INTPTR_MAX? ub: ub - offset);
                    }
                }
                else if (auto *StructTy = llvm::dyn_cast<llvm::StructType>(Ty))
                {
                    // Structure access.  This selects a new sub-object.
                    unsigned elemIdx = K->getZExtValue();
                    Ty = StructTy->getElementType(elemIdx);
                    lb = 0;
                    if (!isFlexibleArrayMember(StructTy, elemIdx))
                        ub = DL.getTypeAllocSize(Ty);
                    else
                        ub = INTPTR_MAX; 
                }
            }
            return std::make_pair(lb, ub);
        }
        case llvm::Instruction::BitCast:
        {
            llvm::Type *Ty = CE->getType();
            auto *PtrTy = llvm::dyn_cast<llvm::PointerType>(Ty);
            if (PtrTy != nullptr && PtrTy->getElementType()->isIntegerTy(8))
                return calculateBoundsConstant(DL, CE->getOperand(0));
            else
                return EMPTY_BOUNDS;
        }
        case llvm::Instruction::Select:
        {
            auto *Cmp = llvm::dyn_cast<llvm::ConstantInt>(CE->getOperand(0));
            if (Cmp == nullptr)
                return EMPTY_BOUNDS;
            return (Cmp->isZero()?
                calculateBoundsConstant(DL, CE->getOperand(2)) :
                calculateBoundsConstant(DL, CE->getOperand(1)));
        }
        case llvm::Instruction::IntToPtr:
        case llvm::Instruction::ExtractElement:
        case llvm::Instruction::ExtractValue:
            return WIDE_BOUNDS;     // Assumed non-fat
        default:
            return WIDE_BOUNDS;
        }
    }
    else if (auto *GV = llvm::dyn_cast<llvm::GlobalVariable>(Ptr))
    {
        if (!canInstrumentGlobal(*GV))
            return WIDE_BOUNDS;
        
        // We trust the static type:
        llvm::Type *Ty = GV->getType();
        auto *PtrTy = llvm::dyn_cast<llvm::PointerType>(Ty);
        Ty = PtrTy->getElementType();
        intptr_t lb = 0;
        intptr_t ub = DL.getTypeAllocSize(Ty);
        return std::make_pair(lb, ub);
    }
    else
        return WIDE_BOUNDS;
}

/*
 * Insert a dynamic bounds narrowing operation.
 */
static llvm::Value *narrowBounds(llvm::Module &M, const InsertPoint &IP,
    llvm::Value *Ptr, const BoundsEntry &Entry)
{
    if (Entry.lb == INTPTR_MIN && Entry.ub == INTPTR_MAX)
        return Entry.bounds;
    llvm::IRBuilder<> builder(IP.bb, IP.itr);
    llvm::Value *IPtr = builder.CreatePtrToInt(Ptr, builder.getInt64Ty());
    llvm::Value *LB = nullptr;
    if (Entry.lb == INTPTR_MIN)
        LB = builder.getInt64(INTPTR_MIN);
    else
        LB = builder.CreateAdd(IPtr, builder.getInt64(Entry.lb));
    llvm::Value *UB = nullptr;
    if (Entry.ub == INTPTR_MAX)
        UB = builder.getInt64(INTPTR_MAX);
    else
        UB = builder.CreateAdd(IPtr, builder.getInt64(Entry.ub));
    llvm::Value *SubBounds = llvm::UndefValue::get(BoundsTy);
    SubBounds = builder.CreateInsertElement(SubBounds, LB, builder.getInt32(0));
    SubBounds = builder.CreateInsertElement(SubBounds, UB, builder.getInt32(1));
    if (Entry.bounds == BoundsNonFat)
        return SubBounds;
    else
    {
        llvm::Constant *Narrow = M.getOrInsertFunction(
            "effective_bounds_narrow", BoundsTy, BoundsTy, BoundsTy, nullptr);
        llvm::Value *Bounds = builder.CreateCall(Narrow,
            {Entry.bounds, SubBounds});
        return Bounds;
    }
}

/*
 * Insert a bounds narrowing operation for part of a GEP instruction.  This
 * will possibly create a new GEP to the desired sub-object.
 */
static llvm::Value *narrowBoundsGEP(llvm::Module &M, llvm::Function &F,
    llvm::GEPOperator *GEP, const InsertPoint &IP, int idx,
    llvm::Value *Bounds, ssize_t lb, ssize_t ub)
{
    if (lb == INTPTR_MIN && ub == INTPTR_MAX)
        return Bounds;

    // Build a GEP to the sub-object.
    // NOTE: This may rebuild the entire GEP.  We rely on CSE to fix.
    llvm::Value *Ptr = GEP->getPointerOperand();
    BoundsEntry Entry = {Bounds, lb, ub};
    if (idx > 0)
    {
        llvm::IRBuilder<> builder(IP.bb, IP.itr);
        std::vector<llvm::Value *> Idxs;
        for (int i = 0; i < idx; i++)
            Idxs.push_back(GEP->getOperand(i+1));
        llvm::Value *Ptr = builder.CreateGEP(GEP->getPointerOperand(), Idxs,
            "subptr");
        InsertPoint IP2 = nextInsertPoint(F, Ptr);
        return narrowBounds(M, IP2, Ptr, Entry);
    }
    else
        return narrowBounds(M, IP, Ptr, Entry);
}

/*
 * Calculate the bounds of a GEP operation.  This will restrict the bounds to
 * any sub-object that was selected, as well as insert any necessary dynamic
 * bounds narrowing operations if needed.
 */
static BoundsEntry calculateBoundsGEP(llvm::Module &M, llvm::Function &F,
    llvm::GEPOperator *GEP, const InsertPoint &IP, TypeInfo &tInfo,
    CheckInfo &cInfo, BoundsInfo &bInfo)
{
    llvm::Value *Ptr = GEP->getPointerOperand();
    llvm::Type *Ty   = Ptr->getType();
    const BoundsEntry &Entry = calculateBounds(M, F, Ptr, tInfo, cInfo, bInfo);
    llvm::Value *Bounds = Entry.bounds;
    ssize_t lb = Entry.lb;
    ssize_t ub = Entry.ub;
    int numIdxs = GEP->getNumIndices();
    const llvm::DataLayout &DL = M.getDataLayout();
    for (int i = 0; i < numIdxs; i++)
    {
        llvm::Value *Idx = GEP->getOperand(i+1);
        llvm::ConstantInt *K = llvm::dyn_cast<llvm::ConstantInt>(Idx);
        if (auto *PtrTy = llvm::dyn_cast<llvm::PointerType>(Ty))
        {
            // Pointer arithmetic.  Narrow if (possibly) OOB.
            // Does not select a sub-object.
            Ty = PtrTy->getElementType();
            ssize_t offset = (K == nullptr? 0:
                K->getSExtValue() * DL.getTypeAllocSize(Ty));
            if (K == nullptr || !(lb <= offset && offset < ub))
            {
                Bounds = narrowBoundsGEP(M, F, GEP, IP, i, Bounds, lb, ub);
                lb = INTPTR_MIN, ub = INTPTR_MAX;
            }
            else
            {
                lb = (lb == INTPTR_MIN? lb: lb - offset);
                ub = (ub == INTPTR_MAX? ub: ub - offset);
            }
        }
        else if (auto *ArrayTy = llvm::dyn_cast<llvm::ArrayType>(Ty))
        {
            // Array access.  Narrow if (possibly) OOB.
            // Does not select a sub-object.
            Ty = ArrayTy->getElementType();
            ssize_t k = (K == nullptr? -1: K->getSExtValue());
            if (k < 0 || k >= (ssize_t)ArrayTy->getNumElements())
            {
                Bounds = narrowBoundsGEP(M, F, GEP, IP, i, Bounds, lb, ub);
                lb = INTPTR_MIN;
                ub = INTPTR_MAX;
            }
            else
            {
                ssize_t offset = k * DL.getTypeAllocSize(Ty);
                lb = (lb == INTPTR_MIN? lb: lb - offset);
                ub = (ub == INTPTR_MAX? ub: ub - offset);
            }
        }
        else if (auto *StructTy = llvm::dyn_cast<llvm::StructType>(Ty))
        {
            // Structure access.  This always selects a new sub-object.
            unsigned elemIdx = K->getZExtValue();
            Ty = StructTy->getElementType(elemIdx);
            lb = 0;
            if (!isFlexibleArrayMember(StructTy, elemIdx))
                ub = DL.getTypeAllocSize(Ty);
            else
                ub = INTPTR_MAX; 
        }
        else
            EFFECTIVE_DEBUG_PRINT("warning: unhandled case!\n");
    }

    BoundsEntry Result = {Bounds, lb, ub};
    return Result;
}

/*
 * Calculate the bounds of a given pointer.  The bounds for `Ptr' are
 * represented as a triple <Bounds, lb, ub>:
 *  - Bounds: the run-time bounds (vector of 2xi64); and
 *  - lb..ub: a representation sub-object bounds (Ptr+lb..Ptr+ub).
 * The actual bounds of `Ptr' at any given point is therefore:
 *    Bounds \cap Ptr+lb..Ptr+ub
 * We also maintain the invariant that:
 *    0 \in lb..ub
 * Thus, `Ptr' is always "in bounds" w.r.t. the type.
 *
 * The motivation of this representation is that we attempt to propagate the
 * sub-object bounds as far as possible "statically".  If bounds cannot be
 * propagated past a given operation (e.g. array index a[i] where `i' is a
 * non-constant), then we insert a "bounds narrowing operation" that computes
 *    NewBounds = Bounds \cap Ptr+lb..Ptr+ub
 * at runtime.  Thus the bounds will becomes fully dynamic <Bounds, -oo, +oo>
 * which can be propagated through "anything".
 */
static const BoundsEntry &calculateBounds(llvm::Module &M, llvm::Function &F,
    llvm::Value *Ptr, TypeInfo &tInfo, CheckInfo &cInfo, BoundsInfo &bInfo)
{
    auto i = bInfo.find(Ptr);
    if (i != bInfo.end())
        return i->second;       // Cached value.

    auto j = cInfo.find(Ptr);
    if (j != cInfo.end())
    {
        llvm::Value *Bounds = j->second.bounds; // Ptr has been type-checked;
                                                // return the calculated bounds.
        BoundsEntry Entry = {Bounds, INTPTR_MIN, INTPTR_MAX};
        auto k = bInfo.insert(std::make_pair(Ptr, Entry));
        return k.first->second;
    }

    llvm::Value *Bounds = BoundsNonFat;
    ssize_t lb = INTPTR_MIN;
    ssize_t ub = INTPTR_MAX;
    if ((option_no_globals && llvm::isa<llvm::Constant>(Ptr)) ||
        (option_no_stack   && llvm::isa<llvm::AllocaInst>(Ptr)))
        /*NOP*/;
    else if (auto *CE = llvm::dyn_cast<llvm::ConstantExpr>(Ptr))
    {
        switch (CE->getOpcode())
        {
        case llvm::Instruction::GetElementPtr:
        {
            auto *GEPOp = llvm::dyn_cast<llvm::GEPOperator>(CE);
            InsertPoint IP = nextInsertPoint(F, Ptr);
            auto [Bounds1, lb1, ub1] = calculateBoundsGEP(M, F, GEPOp, IP,
                tInfo, cInfo, bInfo);
            Bounds = Bounds1; lb = lb1; ub = ub1;
            break;
        }
        case llvm::Instruction::BitCast:
        {
            llvm::Type *Ty = CE->getType();
            auto *PtrTy = llvm::dyn_cast<llvm::PointerType>(Ty);
            if (PtrTy != nullptr && PtrTy->getElementType()->isIntegerTy(8))
            {
                // Constant cast to (char *) is allowed:
                const BoundsEntry &Entry = calculateBounds(M, F,
                    CE->getOperand(0), tInfo, cInfo, bInfo);
                Bounds = Entry.bounds; lb = Entry.lb; ub = Entry.ub;
                break;
            }

            // This case is not handled since there is currently no way to
            // attach metadata to constants.
            std::string msg("unable to instrument constant pointer cast; "
                "type will be treated as (char[])");
            warning(M, msg);

            llvm::Value *Bounds = instrumentTypeCheck(M, F, Ptr, tInfo, cInfo,
                /*untyped=*/true);
            BoundsEntry Entry = {Bounds, INTPTR_MIN, INTPTR_MAX};
            auto k = bInfo.insert(std::make_pair(Ptr, Entry));
            return k.first->second;
        }
        case llvm::Instruction::Select:
        {
            auto *Cmp = llvm::dyn_cast<llvm::ConstantInt>(CE->getOperand(0));
            if (Cmp == nullptr)
            {
                std::string msg("unable to instrument constant (?:) "
                    "expression; type will be treated as (char[])");
                warning(M, msg);

                llvm::Value *Bounds = instrumentTypeCheck(M, F, Ptr, tInfo,
                    cInfo, /*untyped=*/true);
                BoundsEntry Entry = {Bounds, INTPTR_MIN, INTPTR_MAX};
                auto k = bInfo.insert(std::make_pair(Ptr, Entry));
                return k.first->second;
            }
            const BoundsEntry &Entry = (Cmp->isZero()?
                calculateBounds(M, F, CE->getOperand(2), tInfo, cInfo, bInfo) :
                calculateBounds(M, F, CE->getOperand(1), tInfo, cInfo, bInfo));
            Bounds = Entry.bounds; lb = Entry.lb; ub = Entry.ub;
            break;
        }
        case llvm::Instruction::IntToPtr:
        case llvm::Instruction::ExtractElement:
        case llvm::Instruction::ExtractValue:
            break;      // Assumed non-fat
        default:
            EFFECTIVE_FATAL_ERROR("unknown constexpr");
        }
    }
    else if (auto *GV = llvm::dyn_cast<llvm::GlobalVariable>(Ptr))
    {
        if (canInstrumentGlobal(*GV))
        {
            // We trust the static type:
            llvm::Type *Ty = GV->getType();
            auto *PtrTy = llvm::dyn_cast<llvm::PointerType>(Ty);
            Ty = PtrTy->getElementType();
            const llvm::DataLayout &DL = M.getDataLayout();
            lb = 0;
            ub = DL.getTypeAllocSize(Ty);
            if (ub == 0)
            {
                // This is likely a global declared with an incomplete
                // type, e.g. (extern int a[]).  We do not trust the empty
                // bounds; so get the dynamic bounds instead.
                llvm::Value *Bounds = instrumentTypeCheck(M, F, Ptr, tInfo,
                    cInfo, /*untyped=*/true);
                BoundsEntry Entry = {Bounds, INTPTR_MIN, INTPTR_MAX};
                auto k = bInfo.insert(std::make_pair(Ptr, Entry));
                return k.first->second;
            }
        }
    }
    else if (auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(Ptr))
    {
        auto *GEPOp = llvm::dyn_cast<llvm::GEPOperator>(GEP);
        InsertPoint IP = nextInsertPoint(F, Ptr);
        auto [Bounds1, lb1, ub1] = calculateBoundsGEP(M, F, GEPOp, IP, tInfo,
            cInfo, bInfo);
        Bounds = Bounds1; lb = lb1; ub = ub1;
    }
    else if (auto *Cast = llvm::dyn_cast<llvm::BitCastInst>(Ptr))
    {
        llvm::Type *SubObjTy = nullptr;
        if (canIgnoreBitCast(Cast, cInfo, &SubObjTy))
        {
            const BoundsEntry &Entry = calculateBounds(M, F,
                Cast->getOperand(0), tInfo, cInfo, bInfo);
            Bounds = Entry.bounds;
            lb = Entry.lb;
            ub = Entry.ub;
            if (SubObjTy != nullptr)
            {
                const llvm::DataLayout &DL = M.getDataLayout();
                lb = 0;
                ub = DL.getTypeAllocSize(SubObjTy);
            }
        }
        else
        {
            llvm::Value *Bounds = instrumentTypeCheck(M, F, Ptr, tInfo, cInfo);
            BoundsEntry Entry = {Bounds, INTPTR_MIN, INTPTR_MAX};
            auto k = bInfo.insert(std::make_pair(Ptr, Entry));
            return k.first->second;
        }
    }
    else if (auto *Select = llvm::dyn_cast<llvm::SelectInst>(Ptr))
    {
        llvm::Value *PtrA = Select->getOperand(1);
        llvm::Value *PtrB = Select->getOperand(2);
        const BoundsEntry &EntryA = calculateBounds(M, F, PtrA, tInfo, cInfo,
            bInfo);
        const BoundsEntry &EntryB = calculateBounds(M, F, PtrB, tInfo, cInfo,
            bInfo);
        if (EntryA.lb == EntryB.lb && EntryA.ub == EntryB.ub)
        {
            if (EntryA.bounds != EntryB.bounds)
            {
                llvm::IRBuilder<> builder(Select);
                Bounds = builder.CreateSelect(Select->getOperand(0),
                    EntryA.bounds, EntryB.bounds);
            }
            lb = EntryA.lb;
            ub = EntryA.ub;
        }
        else
        {
            InsertPoint IP = nextInsertPoint(F, Select);
            llvm::Value *BoundsA = narrowBounds(M, IP, PtrA, EntryA);
            llvm::Value *BoundsB = narrowBounds(M, IP, PtrB, EntryB);
            llvm::IRBuilder<> builder(Select);
            Bounds = builder.CreateSelect(Select->getOperand(0), BoundsA,
                BoundsB);
        }
    }
    else if (auto *PHI = llvm::dyn_cast<llvm::PHINode>(Ptr))
    {
        unsigned numValues = PHI->getNumIncomingValues();
        llvm::IRBuilder<> builder(PHI);
        llvm::PHINode *BoundsPHI = builder.CreatePHI(BoundsTy, numValues);
        BoundsEntry EntryPHI0 = {BoundsPHI, INTPTR_MIN, INTPTR_MAX};
        auto k = bInfo.insert(std::make_pair(Ptr, EntryPHI0));
        BoundsEntry &EntryPHI = k.first->second;

        ssize_t lb1 = INTPTR_MIN, ub1 = INTPTR_MAX;
        bool haveSubBounds = false, allSameSubBounds = true;
        for (unsigned i = 0; i < numValues; i++)
        {
            llvm::Value *PtrIn = PHI->getIncomingValue(i);
            const BoundsEntry &EntryIn = calculateBounds(M, F, PtrIn, tInfo,
                cInfo, bInfo);
            BoundsPHI->addIncoming(EntryIn.bounds, PHI->getIncomingBlock(i));
            if (llvm::isa<llvm::ConstantPointerNull>(PtrIn))
                continue;   // NULL does not count since access is undefined
                            // anyway.
            if (!haveSubBounds)
            {
                lb1 = EntryIn.lb;
                ub1 = EntryIn.ub;
                haveSubBounds = true;
            }
            else
                allSameSubBounds = allSameSubBounds &&
                    (lb1 == EntryIn.lb && ub1 == EntryIn.ub);
        }
        if (allSameSubBounds)
        {
            // All incoming bounds select the same sub-object bounds; thus
            // there is no need to do any narrowing.
            EntryPHI.lb = lb1;
            EntryPHI.ub = ub1;
            return EntryPHI;
        }
        else
        {
            // Some or all of the incoming bounds have different sub-object
            // bounds.  Since these cannot be merged, we must narrow.
            for (unsigned i = 0; i < numValues; i++)
            {
                llvm::Value *PtrIn = PHI->getIncomingValue(i);
                const BoundsEntry &EntryIn = calculateBounds(M, F, PtrIn,
                    tInfo, cInfo, bInfo);
                llvm::BasicBlock *BBIn = PHI->getIncomingBlock(i);
                llvm::BasicBlock::iterator j(BBIn->getTerminator());
                InsertPoint IP = {BBIn, j};
                llvm::Value *BoundsIn = narrowBounds(M, IP, PtrIn, EntryIn);
                BoundsPHI->setIncomingValue(i, BoundsIn);
            }
            EntryPHI.lb = INTPTR_MIN;
            EntryPHI.ub = INTPTR_MAX;
            return EntryPHI;
        }
    }
    else if (llvm::isa<llvm::ConstantPointerNull>(Ptr) ||
             llvm::isa<llvm::GlobalObject>(Ptr) ||
             llvm::isa<llvm::UndefValue>(Ptr))
        /*NOP*/;
    else if (llvm::isa<llvm::CallInst>(Ptr) ||
             llvm::isa<llvm::InvokeInst>(Ptr) ||
             llvm::isa<llvm::AllocaInst>(Ptr) ||
             llvm::isa<llvm::Argument>(Ptr) ||
             llvm::isa<llvm::IntToPtrInst>(Ptr) ||
             llvm::isa<llvm::LoadInst>(Ptr) ||
             llvm::isa<llvm::ExtractValueInst>(Ptr) ||
             llvm::isa<llvm::ExtractElementInst>(Ptr))
    {
        llvm::Value *Bounds = instrumentTypeCheck(M, F, Ptr, tInfo, cInfo);
        BoundsEntry Entry = {Bounds, INTPTR_MIN, INTPTR_MAX};
        auto k = bInfo.insert(std::make_pair(Ptr, Entry));
        return k.first->second;
    }
    else
        EFFECTIVE_FATAL_ERROR("unknown value");

    BoundsEntry Entry = {Bounds, lb, ub};
    auto k = bInfo.insert(std::make_pair(Ptr, Entry));
    return k.first->second;
}

/*
 * Insert a bounds check.  Also "widens" the bounds as much as possible.
 */
static bool insertBoundsCheck(const llvm::DataLayout &DL, llvm::Instruction *I,
    llvm::Value *Ptr, llvm::Value *Ptr0, ssize_t offset, size_t size,
    llvm::Value *Size, bool escape, const CheckInfo &cInfo,
    BoundsCheckInfo &bcInfo, bool force = false)
{
    if (size == SIZE_MAX)
    {
        // Don't bother widening if size is unknown.
        ;
    }
    else if (auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(Ptr))
    {
        // Attempt to widen the GEP.
        llvm::APInt Offset(64, offset);
        if (GEP->accumulateConstantOffset(DL, Offset))
        {
            // Constant GEP.  Check for sub-object OOB:
            int numIdxs = GEP->getNumIndices();
            llvm::Type *Ty = GEP->getPointerOperand()->getType();
            bool isOOB = false;
            for (int i = 0; !isOOB && i < numIdxs; i++)
            {
                llvm::Value *Idx = GEP->getOperand(i+1);
                llvm::ConstantInt *Int = llvm::dyn_cast<llvm::ConstantInt>(Idx);
                if (Int == nullptr)
                    EFFECTIVE_FATAL_ERROR("non-const index");
                else if (auto *PtrTy = llvm::dyn_cast<llvm::PointerType>(Ty))
                    Ty = PtrTy->getElementType();
                else if (auto *ArrayTy = llvm::dyn_cast<llvm::ArrayType>(Ty))
                {
                    Ty = ArrayTy->getElementType();
                    ssize_t idx = Int->getSExtValue();
                    isOOB =
                        (idx < 0 || idx >= (ssize_t)ArrayTy->getNumElements());
                }
                else if (auto *StructTy = llvm::dyn_cast<llvm::StructType>(Ty))
                {
                    unsigned field = Int->getZExtValue();
                    Ty = StructTy->getElementType(field);
                }
                else
                    EFFECTIVE_FATAL_ERROR("unknown type");
            }

            if (!isOOB)
            {
                // Can possibly widen beyond this GEP.
                ssize_t offset = Offset.getSExtValue();
                if (insertBoundsCheck(DL, I, GEP->getPointerOperand(), Ptr0,
                        offset, size, Size, escape, cInfo, bcInfo))
                    return true;
            }
        }
    }
    else if (auto *Cast = llvm::dyn_cast<llvm::BitCastInst>(Ptr))
    {
        llvm::Type *SubObjTy = nullptr;
        if (canIgnoreBitCast(Cast, cInfo, &SubObjTy))
        {
            // If offset>=sizeof(SubObjTy) then the access is OOB, so cannot
            // widen.
            if ((SubObjTy == nullptr ||
                    offset < (ssize_t)DL.getTypeAllocSize(SubObjTy)) &&
                insertBoundsCheck(DL, I, Cast->getOperand(0), Ptr0, offset,
                    size, Size, escape, cInfo, bcInfo))
            {
                return true;
            }
        }
    }

    // Check if the access is within the widened type & adjust if necessary.
    intptr_t lb = 0;
    intptr_t ub = 0;
    if (auto *PtrTy = llvm::dyn_cast<llvm::PointerType>(Ptr->getType()))
        ub = DL.getTypeAllocSize(PtrTy->getElementType());
    else
        EFFECTIVE_FATAL_ERROR("failed to get size");
    if (!force && (offset < lb || offset + (ssize_t)size > ub))
    {
        // Access is OOB of the widened type.
        return false;
    }
    lb = std::min(offset, lb);
    if (size == SIZE_MAX)
        ub = SIZE_MAX;
    else
        ub = std::max(offset + (ssize_t)size, ub);
    if (escape && offset == 0)
    {
        // The escaping pointer might be 1-past-the-end, so we cannot assume
        // lb..ub is within bounds.
        ub = lb;
    }

    // Insert the bounds check:
    std::vector<BoundsCheckEntry> empty;
    auto i = bcInfo.insert(std::make_pair(Ptr, empty)).first;
    bool redundant = false;
    BoundsCheckEntry Check = {Ptr0, I, Ptr, lb, ub, offset, size, Size,
        redundant};
    i->second.push_back(Check);
    return true;
}

/*
 * Insert a bounds check.
 */
static void insertBoundsCheck(const llvm::DataLayout &DL, llvm::Instruction *I,
    llvm::Value *Ptr, size_t size, llvm::Value *Size, bool escape,
    const CheckInfo &cInfo, BoundsCheckInfo &bcInfo)
{
    bool force = true;
    if (!insertBoundsCheck(DL, I, Ptr, Ptr, 0, size, Size, escape, cInfo,
            bcInfo, force))
    {
        EFFECTIVE_FATAL_ERROR("failed to insert bounds check");
    }
}

/*
 * Find all memory operations that need to be bounds-checked.  This includes
 * reads, writes, memset() and memcpy().
 */
static void findPointersForBoundsCheck(llvm::Module &M, llvm::Function &F,
    BoundsCheckInfo &bcInfo, const CheckInfo &cInfo,
    const std::set<llvm::Instruction *> &Ignore)
{
    const llvm::DataLayout &DL = M.getDataLayout();

    for (auto &BB: F)
    {
        for (auto &I: BB)
        {
            if (Ignore.find(&I) != Ignore.end())
                continue;
            llvm::Value *Ptr = getMemoryAccessPtr(I);
            if (Ptr != nullptr)
            {
                size_t size = 0;
                if (auto *PtrTy =
                        llvm::dyn_cast<llvm::PointerType>(Ptr->getType()))
                    size = DL.getTypeAllocSize(PtrTy->getElementType());
                insertBoundsCheck(DL, &I, Ptr, size, nullptr, false, cInfo,
                    bcInfo);
            }
            if (auto *MT = llvm::dyn_cast<llvm::MemTransferInst>(&I))
            {
                size_t size = SIZE_MAX;
                llvm::Value *Size = MT->getOperand(2);
                if (auto *Int = llvm::dyn_cast<llvm::ConstantInt>(Size))
                {
                    Size = nullptr;
                    size = Int->getZExtValue();
                }
                llvm::Value *Src = MT->getOperand(1);
                llvm::Value *Dst = MT->getOperand(0);
                insertBoundsCheck(DL, &I, Src, size, Size, false, cInfo,
                    bcInfo);
                insertBoundsCheck(DL, &I, Dst, size, Size, false, cInfo,
                    bcInfo);
            }
            else if (auto *MS = llvm::dyn_cast<llvm::MemSetInst>(&I))
            {
                size_t size = SIZE_MAX;
                llvm::Value *Size = MS->getOperand(2);
                if (auto *Int = llvm::dyn_cast<llvm::ConstantInt>(Size))
                {
                    Size = nullptr;
                    size = Int->getZExtValue();
                }
                llvm::Value *Dst = MS->getOperand(0);
                insertBoundsCheck(DL, &I, Dst, size, Size, false, cInfo,
                    bcInfo);
            }

            // We also bounds-check "escaping" pointers.  This is to overcome
            // the limitation that the type checker can only retrieve object
            // metadata for in-bound pointers.
            if (option_no_escapes)
                continue;
            std::vector<llvm::Value *> Ptrs;
            getEscapePtrs(DL, I, Ptrs);
            for (auto *Ptr: Ptrs)
                insertBoundsCheck(DL, &I, Ptr, 0, nullptr, true, cInfo,
                    bcInfo);
        }
    }
}

/*
 * Insert a bounds check.
 */
static EFFECTIVE_NOINLINE void instrumentBoundsCheck(llvm::Module &M,
    llvm::Function &F, const BoundsCheckEntry &Check, TypeInfo &tInfo,
    CheckInfo &cInfo, BoundsInfo &bInfo)
{
    if (Check.redundant)
        return;     // Check removed by optimizeBoundsChecks()

    llvm::Value *Ptr = Check.ptr;
    llvm::Instruction *I = Check.instr;
    intptr_t lb = Check.wideLb - Check.accessOffset;
    intptr_t ub = Check.wideUb - Check.accessOffset;

    // Calculate the bounds:
    BoundsEntry Entry = calculateBounds(M, F, Check.widePtr, tInfo, cInfo,
        bInfo);     // copy.
    if (Entry.bounds == BoundsNonFat)
    {
        // This is a non-fat pointer, so no need to do a bounds check.
        return;
    }

    // If the Entry sub-bounds are wider than the check bounds, there is no
    // no need for a narrow operation.  Otherwise, then a this is a static
    // bounds error, so this condition should be rarely triggered, if ever.
    if (Entry.lb > Check.wideLb || Entry.ub < Check.wideUb)
    {
        llvm::BasicBlock::iterator i(I);
        InsertPoint IP = {I->getParent(), i};
        Entry.bounds = narrowBounds(M, IP, Ptr, Entry);
        Entry.lb = INTPTR_MIN;
        Entry.ub = INTPTR_MAX;
    }

    // Emit the bounds check.
    llvm::IRBuilder<> builder(I);
    llvm::Constant *BoundsCheck =
        M.getOrInsertFunction("effective_bounds_check", builder.getVoidTy(),
        BoundsTy, builder.getInt8PtrTy(), builder.getInt64Ty(),
        builder.getInt64Ty(), nullptr);
    Ptr = builder.CreateBitCast(Ptr, builder.getInt8PtrTy());

    llvm::Value *LB = builder.getInt64(lb);
    llvm::Value *UB = nullptr;
    if (Check.accessVarSize == nullptr)
    {
        // Common case: constant-sized access [lb..ub]
        UB = builder.getInt64(ub);
    }
    else
    {
        // Variable-sized access [lb..lb+size]
        if (lb != 0)
            UB = builder.CreateAdd(LB, Check.accessVarSize);
        else
            UB = Check.accessVarSize;
    }
    builder.CreateCall(BoundsCheck, {Entry.bounds, Ptr, LB, UB});
}

/*****************************************************************************/
/* BOUNDS CHECK OPTIMIZATION                                                 */
/*****************************************************************************/

/*
 * Return `true' if *Ptr is within the pointer's allocation bounds, if any.
 */
static bool isWithinAllocationBounds(const llvm::DataLayout &DL,
    const CheckInfo &cInfo, llvm::Value *Ptr, intptr_t lb, intptr_t ub,
    std::map<llvm::Value *, std::pair<intptr_t, intptr_t>> &Seen)
{
    intptr_t alloc_lb = 0, alloc_ub = 0;

    auto i = cInfo.find(Ptr);
    if (i != cInfo.end() && i->second.allocType != nullptr)
    {
        // Ptr is a memory allocation:
        alloc_ub = i->second.allocSize;
    }
    else if (auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(Ptr))
    {
        llvm::APInt Offset(64, 0);
        if (GEP->accumulateConstantOffset(DL, Offset))
        {
            intptr_t offset = Offset.getSExtValue();
            lb += offset;
            ub += offset;
            return isWithinAllocationBounds(DL, cInfo, GEP->getPointerOperand(),
                lb, ub, Seen);
        }
        return false;
    }
    else if (auto *Cast = llvm::dyn_cast<llvm::BitCastInst>(Ptr))
    {
        llvm::Type *SubObjTy = nullptr;
        if (canIgnoreBitCast(Cast, cInfo, &SubObjTy))
        {
            if (SubObjTy == nullptr ||
                    (lb >= 0 && ub <= (ssize_t)DL.getTypeAllocSize(SubObjTy)))
            {
                return isWithinAllocationBounds(DL, cInfo, Cast->getOperand(0),
                    lb, ub, Seen);
            }
        }
        return false;
    }
    else if (auto *PHI = llvm::dyn_cast<llvm::PHINode>(Ptr))
    {
        auto i = Seen.find(Ptr);
        if (i != Seen.end())
        {
            return (i->second.first == lb && i->second.second == ub);
        }
        Seen.insert(std::make_pair(Ptr, std::make_pair(lb, ub)));
        size_t numValues = PHI->getNumIncomingValues();
        for (size_t i = 0; i < numValues; i++)
        {
            if (!isWithinAllocationBounds(DL, cInfo, PHI->getIncomingValue(i),
                    lb, ub, Seen))
                return false;
        }
        return true;
    }
    else if (auto *C = llvm::dyn_cast<llvm::Constant>(Ptr))
    {
        std::pair<intptr_t, intptr_t> Bounds = calculateBoundsConstant(DL, C);
        alloc_lb = Bounds.first;
        alloc_ub = Bounds.second;
    }
    else
        return false;

    return (lb >= alloc_lb && ub <= alloc_ub);
}

/*
 * Optimize away redundant bounds checks.
 * An instruction does not need to be bounds checked if:
 * (1) the pointer is within the statically-known allocation bounds
 * (2) the check is dominated by another instruction that has the same bounds
 *     checked.
 */
static void optimizeBoundsChecks(llvm::Module &M, llvm::Function &F,
    const CheckInfo &cInfo, BoundsCheckInfo &bcInfo)
{
    const llvm::DataLayout &DL = M.getDataLayout();
    const llvm::DominatorTree DT(F);

    for (auto &entry: bcInfo)
    {
        std::vector<BoundsCheckEntry> &Checks = entry.second;

        for (auto &Check: Checks)
        {
            // OPTIMIZATION #1
            // If the bounds check is within the allocation bounds, then it is
            // redundant.
            std::map<llvm::Value *, std::pair<intptr_t, intptr_t>> Seen;
            if (isWithinAllocationBounds(DL, cInfo, Check.widePtr,
                    Check.wideLb, Check.wideUb, Seen))
            {
                Check.redundant = true;
                continue;
            }

            // OPTIMIZATION #2
            // If the bounds check is dominated by another bounds check, then
            // it is redundant.
            for (auto &Check2: Checks)
            {
                if (Check.instr != Check2.instr &&              // different
                        Check2.widePtr == Check.widePtr &&      // true
                        DT.dominates(Check2.instr, Check.instr) &&
                        Check2.wideLb <= Check.wideLb &&
                        Check2.wideUb >= Check.wideUb &&
                        Check2.accessVarSize == Check.accessVarSize &&
                        (Check.accessVarSize != nullptr?
                            Check2.wideLb == Check.wideLb: true))
                {
                    Check.redundant = true;
                    break;
                }
            }
        }
    }
}

/*****************************************************************************/
/* TYPED MEMORY ALLOCATION                                                   */
/*****************************************************************************/

/*
 * malloc()'s return type is (void *).  The typical C idiom is to immediately
 * cast the return value to the desired type.  This function uses a simple
 * heuristic to try and determine what that type is.
 */
static llvm::Constant *inferMallocType(llvm::Module &M, llvm::Function &F,
    llvm::Instruction *I, TypeInfo &tInfo, llvm::DIType **TyPtr = nullptr)
{
    const llvm::DominatorTree DT(F);
    llvm::BitCastInst *Cast = nullptr;
    for (llvm::User *U: I->users())
    {
        if (auto *Next = llvm::dyn_cast<llvm::BitCastInst>(U))
        {
            if (Cast == nullptr)
                Cast = Next;
            else if (DT.dominates(Next, Cast))
                Cast = Next;
            else if (!DT.dominates(Cast, Next) &&
                     Cast->getDestTy() != Next->getDestTy())
                return nullptr;     // Conflicting casts; give up
        }
    }
    return (Cast == nullptr? nullptr:
                             getDeclaredType(M, Cast, tInfo, TyPtr, true));
}

static size_t getSize(llvm::Value *Size)
{
    auto *K = llvm::dyn_cast<llvm::ConstantInt>(Size);
    return (K == nullptr? 0: K->getZExtValue());
}

/*
 * Replace malloc/free with the "typed" version that includes object metadata.
 */
static void replaceMalloc(llvm::Module &M, llvm::Function &F,
    llvm::Instruction &I, TypeInfo &tInfo, CheckInfo &cInfo,
    std::vector<llvm::Instruction *> &Dels)
{
    llvm::CallSite Call(&I);
    if (!Call.isCall() && !Call.isInvoke())
        return;
    llvm::Function *CalledFn = Call.getCalledFunction();
    if (CalledFn == nullptr || !CalledFn->hasName())
        return;

    llvm::StringRef Name = CalledFn->getName(); 
    llvm::Value *Bounds = nullptr;
    llvm::Constant *Meta = nullptr;
    llvm::IRBuilder<> builder(&I);
    llvm::DIType *Ty = nullptr;
    size_t size = 0;
    if ((Call.getNumArgOperands() == 1 &&
            (Name == "malloc" ||
             Name == "_Znwm" ||                     // new
             Name == "_Znam")) ||                   // new[]
        (Call.getNumArgOperands() == 2 &&
            (Name == "_ZnwmRKSt9nothrow_t" ||       // new (nothrow)
             Name == "_ZnamRKSt9nothrow_t")))       // new[] (nothrow)
    {
        // malloc, new, new[]:
        Meta = getDeclaredType(M, &I, tInfo, &Ty, true);
        if (Meta == nullptr)
            Meta = inferMallocType(M, F, &I, tInfo, &Ty);
        Meta = (Meta == nullptr? Int8TyMeta: Meta);
        std::string newName = "effective_";
        newName += Name.str();
        llvm::Constant *NewFn = M.getOrInsertFunction(newName, BoundsTy,
            builder.getInt64Ty(), TypeTy->getPointerTo(), nullptr);
        size = getSize(I.getOperand(0));
        Bounds = builder.CreateCall(NewFn, {I.getOperand(0), Meta});
    }
    else if (Call.getNumArgOperands() == 2 && Name == "calloc")
    {
        // calloc:
        Meta = inferMallocType(M, F, &I, tInfo, &Ty);
        Meta = (Meta == nullptr? Int8TyMeta: Meta);
        llvm::Constant *NewFn = M.getOrInsertFunction("effective_calloc",
            BoundsTy, builder.getInt64Ty(), builder.getInt64Ty(),
            TypeTy->getPointerTo(), nullptr);
        size = getSize(I.getOperand(0)) * getSize(I.getOperand(1));
        Bounds = builder.CreateCall(NewFn, {I.getOperand(0), I.getOperand(1),
            Meta});
    }
    else if (Call.getNumArgOperands() == 2 && Name == "realloc")
    {
        // realloc:
        llvm::Constant *NewFn = M.getOrInsertFunction("effective_realloc",
            BoundsTy, builder.getInt8PtrTy(), builder.getInt64Ty(), nullptr);
        size = getSize(I.getOperand(1));
        Bounds = builder.CreateCall(NewFn, {I.getOperand(0), I.getOperand(1)});
    }
    else if (Call.getNumArgOperands() == 1 &&
            (Name == "free" ||
             Name == "_ZdlPv" ||                    // delete
             Name == "_ZdaPv"))                     // delete[]
    {
        // free, delete, delete[]:
        std::string newName = "effective_";
        newName += Name.str();
        llvm::Constant *NewFn = M.getOrInsertFunction(newName,
            builder.getVoidTy(), builder.getInt8PtrTy(), nullptr);
        builder.CreateCall(NewFn, {I.getOperand(0)});
        Dels.push_back(&I);
        return;
    }
    else
        return;

    // EffectiveSan's heap allocator returns object bounds.
    // The allocated pointer is the first element.
    llvm::Value *NewPtr = builder.CreateExtractElement(Bounds,
        builder.getInt32(0));
    NewPtr = builder.CreateIntToPtr(NewPtr, builder.getInt8PtrTy());
    Ty = (Ty == nullptr? Int8Ty: Ty);
    CheckEntry Entry = {Bounds, Ty, size};
    cInfo.insert(std::make_pair(NewPtr, Entry));
    I.replaceAllUsesWith(NewPtr);
    if (auto *Invoke = llvm::dyn_cast<llvm::InvokeInst>(&I))
    {
        // EffectiveSan's "new" will never throw; so we just jump to the
        // normal destination.
        builder.CreateBr(Invoke->getNormalDest());
    }
    Dels.push_back(&I);
}

static EFFECTIVE_NOINLINE void replaceMallocs(llvm::Module &M,
    llvm::Function &F, TypeInfo &tInfo, CheckInfo &cInfo)
{
    std::vector<llvm::Instruction *> Dels;
    for (auto &BB: F)
    {
        for (auto &I: BB)
            replaceMalloc(M, F, I, tInfo, cInfo, Dels);
    }
    for (auto I: Dels)
        I->eraseFromParent();
}

/*
 * Convert an alloca instruction into a low-fat-pointer and wrap the
 * allocation with object metadata.  This is a modified version of the
 * low-fat stack allocator, see:
 * - "Stack Bounds Protection..." NDSS'17
 * - https://github.com/GJDuck/LowFat
 */
static void replaceAlloca(llvm::Module &M, llvm::Function &F,
    llvm::Instruction &I, TypeInfo &tInfo, CheckInfo &cInfo,
    std::set<llvm::Instruction *> &Ignore,
    std::vector<llvm::Instruction *> &Dels)
{
    if (option_no_stack)
        return;
    auto Alloca = llvm::dyn_cast<llvm::AllocaInst>(&I);
    if (Alloca == nullptr)
        return;
    auto i = Ignore.find(Alloca);
    if (i != Ignore.end())
        return;

    const llvm::DataLayout &DL = M.getDataLayout();
    llvm::Value *Size = Alloca->getArraySize();
    llvm::ConstantInt *ISize = llvm::dyn_cast<llvm::ConstantInt>(Size);
    if (ISize == nullptr)
    {
        // TODO: EffectiveSan does not currently support VLAs.
        return;
    }
    llvm::Type *Ty = Alloca->getAllocatedType();
    if (!Ty->isSized())
        return;

    auto j = nextInsertPoint(F, Alloca);
    llvm::IRBuilder<> builder(j.bb, j.itr);
    llvm::Value *Offset = nullptr, *AllocedPtr = nullptr;
    llvm::Value *NoReplace1 = nullptr, *NoReplace2 = nullptr,
                *NoReplace3 = nullptr;
    llvm::Value *CastAlloca = nullptr;
    llvm::Value *LifetimeSize = nullptr;
    bool delAlloca = false;
    size_t len = 0, objSize = 0, allocSize = 0;

    // Aligned allocas not supported.
    // TODO: aligned(16) will be ignored!
    if (Alloca->getAlignment() > 16)
        return;

    // Simple+common case: fixed sized alloca:
    len = ISize->getZExtValue();
    objSize = DL.getTypeAllocSize(Ty) * len;
    allocSize = objSize + sizeof(EFFECTIVE_META);

    // STEP (1): Align the stack:
    size_t idx = (allocSize == 0? 64: EFFECTIVE_CLZLL(allocSize));
    ssize_t offset = lowfat_stack_offsets[idx];
    if (idx > 64 || offset == 0)
        return;
    size_t align = ~lowfat_stack_masks[idx] + 1;
    if (align > Alloca->getAlignment())
        Alloca->setAlignment(align);

    // STEP (2): Adjust the allocation size:
    size_t newSize = lowfat_stack_sizes[idx];
    if (newSize != allocSize)
    {
        LifetimeSize = builder.getInt64(newSize);
        llvm::AllocaInst *NewAlloca = builder.CreateAlloca(builder.getInt8Ty(),
            LifetimeSize);
        Ignore.insert(NewAlloca);
        NewAlloca->setAlignment(Alloca->getAlignment());
        AllocedPtr = NewAlloca;
        delAlloca = true;
    }
    else
        AllocedPtr = builder.CreateBitCast(Alloca, builder.getInt8PtrTy());
    CastAlloca = AllocedPtr;
    NoReplace1 = AllocedPtr;
    Offset = builder.getInt64(offset);

    // STEP (3): Teleport the pointer into a low-fat region:
    llvm::Constant *MirrorFunc = M.getOrInsertFunction("lowfat_stack_mirror_2",
        builder.getInt8PtrTy(), builder.getInt8PtrTy(), builder.getInt64Ty(),
        nullptr);
    llvm::Value *MirroredPtr = builder.CreateCall(MirrorFunc,
        {AllocedPtr, Offset});
    if (auto *Call = llvm::dyn_cast<llvm::CallInst>(MirroredPtr))
        Ignore.insert(Call);
    NoReplace3 = MirroredPtr;
    llvm::Value *Ptr0 = builder.CreateGEP(MirroredPtr,
        builder.getInt32(sizeof(EFFECTIVE_META)));
    llvm::Value *Ptr = builder.CreateBitCast(Ptr0, Alloca->getType());

    // STEP (4) Insert the object meta data:
    llvm::DIType *AllocTy = nullptr;
    llvm::Constant *Meta = getDeclaredType(M, &I, tInfo, &AllocTy, true);
    if (Meta == nullptr)
    {
        // Fall back on type inference.
        Meta = inferMallocType(M, F, &I, tInfo, &AllocTy);
    }
    Meta = (Meta == nullptr? Int8TyMeta: Meta);
    llvm::Value *MetaPtr = builder.CreateBitCast(MirroredPtr,
        ObjMetaTy->getPointerTo());
    llvm::Value *TypePtr = builder.CreateGEP(MetaPtr,
        {builder.getInt32(0), builder.getInt32(0)});
    llvm::StoreInst *Store = builder.CreateAlignedStore(Meta, TypePtr,
        sizeof(void *));
    Ignore.insert(Store);
    llvm::Value *SizePtr = builder.CreateGEP(MetaPtr,
        {builder.getInt32(0), builder.getInt32(1)});
    Store = builder.CreateAlignedStore(builder.getInt64(objSize), SizePtr,
        sizeof(void *));
    Ignore.insert(Store);

    // STEP (5): Calculate bounds:
    llvm::Value *LB = builder.CreatePtrToInt(Ptr0, builder.getInt64Ty());
    if (auto *Ptr2Int = llvm::dyn_cast<llvm::PtrToIntInst>(LB))
        Ignore.insert(Ptr2Int);
    llvm::Value *Undef = llvm::UndefValue::get(BoundsTy);
    llvm::Value *Bounds = builder.CreateInsertElement(Undef, LB,
        builder.getInt32(0));
    llvm::Value *UB = builder.CreateGEP(Ptr0, builder.getInt32(objSize));
    UB = builder.CreatePtrToInt(UB, builder.getInt64Ty());
    if (auto *Ptr2Int = llvm::dyn_cast<llvm::PtrToIntInst>(UB))
        Ignore.insert(Ptr2Int);
    Bounds = builder.CreateInsertElement(Bounds, UB, builder.getInt32(1));
    CheckEntry Entry = {Bounds, AllocTy, objSize};
    cInfo.insert(std::make_pair(Ptr, Entry));

    // Replace all uses of `Alloca' with the (now low-fat) `Ptr'.
    // (except for lifetime intrinsics).
    std::vector<llvm::User *> Replace;  // Lifetimes;
    for (llvm::User *Usr: Alloca->users())
    {
        if (Usr == NoReplace1 || Usr == NoReplace2 || Usr == NoReplace3)
            continue;
        if (auto Intr = llvm::dyn_cast<llvm::IntrinsicInst>(Usr))
        {
            if (Intr->getIntrinsicID() == llvm::Intrinsic::lifetime_start ||
                Intr->getIntrinsicID() == llvm::Intrinsic::lifetime_end)
            {
                Dels.push_back(Intr);
                continue;
            }
        }
        if (auto Cast = llvm::dyn_cast<llvm::BitCastInst>(Usr))
        {
            for (llvm::User *Usr2: Cast->users())
            {
                auto Intr = llvm::dyn_cast<llvm::IntrinsicInst>(Usr2);
                if (Intr == nullptr)
                    continue;
                if (Intr->getIntrinsicID() == llvm::Intrinsic::lifetime_start ||
                    Intr->getIntrinsicID() == llvm::Intrinsic::lifetime_end)
                    Dels.push_back(Intr);
            }
        }
        Replace.push_back(Usr);
    }
    for (llvm::User *Usr: Replace)
        Usr->replaceUsesOfWith(Alloca, Ptr);

    if (delAlloca)
        Dels.push_back(Alloca);
}

static EFFECTIVE_NOINLINE void replaceAllocas(llvm::Module &M,
    llvm::Function &F, TypeInfo &tInfo, CheckInfo &cInfo,
    std::set<llvm::Instruction *> &Ignore)
{
    std::vector<llvm::Instruction *> Dels;
    for (auto &BB: F)
    {
        for (auto &I: BB)
            replaceAlloca(M, F, I, tInfo, cInfo, Ignore, Dels);
    }
    for (auto I: Dels)
        I->eraseFromParent();
}

/*
 * Decide if the given global variable can be instrumented or not.
 */
static bool canInstrumentGlobal(llvm::GlobalVariable &GV)
{
    if (option_no_globals)
        return false;
    if (GV.hasSection())            // User-declared section
        return false;
    if (GV.getAlignment() > 16)     // User-declared alignment
        return false;
    if (GV.isThreadLocal())         // TLS not supported
        return false;
    llvm::Type *Ty = GV.getType();
    while (auto *PtrTy = llvm::dyn_cast<llvm::PointerType>(Ty))
        Ty = PtrTy->getElementType();
    if (Ty->isFunctionTy())
    {
        // Function types are not supported, since this is a source of bugs
        // when building firefox with mcmodel=large
        return false;
    }
    switch (GV.getLinkage())
    {
    case llvm::GlobalValue::ExternalLinkage:
    case llvm::GlobalValue::InternalLinkage:
    case llvm::GlobalValue::PrivateLinkage:
    case llvm::GlobalValue::WeakAnyLinkage:
    case llvm::GlobalValue::WeakODRLinkage:
    case llvm::GlobalValue::CommonLinkage:
        break;
    default:
        return false;               // No fancy linking types supported.
    }
    if (GV.hasName())
    {
        llvm::StringRef Name = GV.getName();
        const char prefix[] = "EFFECTIVE_";
        if (Name.str().compare(0, sizeof(prefix)-1, prefix) == 0)
            return false;           // EffectiveSan internal GV.
        if (isBlacklisted("global", Name))
            return false;
    }
    return true;
}

/*
 * Convert a global variable into a low-fat-pointer and wrap with the object
 * metadata.  For more details, see the technical report "An Extended Low Fat
 * Allocator API and Applications", 2018.
 */
static void replaceGlobal(llvm::Module &M, llvm::GlobalVariable &GV,
    TypeInfo &tInfo, std::vector<llvm::GlobalVariable *> &Dels)
{
    if (GV.isDeclaration())
        return;
    if (!canInstrumentGlobal(GV))
        return;

    llvm::Type *Ty = GV.getType();
    llvm::PointerType *PtrTy = llvm::dyn_cast<llvm::PointerType>(Ty);
    Ty = PtrTy->getElementType();
    if (!Ty->isSized())
        return;
    const llvm::DataLayout &DL = M.getDataLayout();
    size_t objSize = DL.getTypeAllocSize(Ty);
    size_t allocSize = objSize + sizeof(EFFECTIVE_META);
    size_t idx = EFFECTIVE_CLZLL(allocSize);
    if (idx <= EFFECTIVE_CLZLL(LOWFAT_MAX_GLOBAL_ALLOC_SIZE))
        return;
    size_t align = ~lowfat_stack_masks[idx] + 1;
    size_t newSize = lowfat_stack_sizes[idx];

    std::string NewName("EFFECTIVE_GLOBAL_WRAPPER_");
    NewName += GV.getName();
    llvm::LLVMContext &Cxt = M.getContext();
    llvm::StructType *NewTy = llvm::StructType::create(Cxt, {ObjMetaTy, Ty}, 
        "EFFECTIVE_GLOBAL_WRAPPER", /*isPacked=*/true);
    llvm::Constant *NewGV0 = M.getOrInsertGlobal(NewName, NewTy);
    llvm::GlobalVariable *NewGV = llvm::dyn_cast<llvm::GlobalVariable>(NewGV0);
    if (NewGV == nullptr)
        return;

    if (GV.getLinkage() == llvm::GlobalValue::CommonLinkage)
    {
        // Convert common symbols into weak symbols:
        NewGV->setLinkage(llvm::GlobalValue::WeakAnyLinkage);
    }
    else
        NewGV->setLinkage(GV.getLinkage());
    NewGV->setAlignment(align);
    std::string section("lowfat_section_");
    if (GV.isConstant())
        section += "const_";
    section += std::to_string(newSize);
    NewGV->setSection(section);

    llvm::Constant *Meta = getDeclaredType(M, &GV, tInfo, nullptr, true);
    Meta = (Meta == nullptr? Int8TyMeta: Meta);
    llvm::Constant *MetaInit = llvm::ConstantStruct::get(ObjMetaTy,
        {Meta, llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt), objSize)});
    llvm::Constant *Init = nullptr;
    if (GV.hasInitializer())
        Init = GV.getInitializer();
    else
        Init = llvm::ConstantAggregateZero::get(Ty);
    Init = llvm::ConstantStruct::get(NewTy, {MetaInit, Init});
    NewGV->setInitializer(Init);

    llvm::Constant *Idxs[] =
        {llvm::ConstantInt::get(llvm::Type::getInt32Ty(Cxt), 0),
         llvm::ConstantInt::get(llvm::Type::getInt32Ty(Cxt), 1)};
    llvm::Constant *NewGV1 = llvm::ConstantExpr::getInBoundsGetElementPtr(
        NewTy, NewGV, Idxs);
    GV.replaceAllUsesWith(NewGV1);
    Dels.push_back(&GV);

    switch (GV.getLinkage())
    {
    case llvm::GlobalValue::ExternalLinkage:
    case llvm::GlobalValue::WeakAnyLinkage:
    case llvm::GlobalValue::WeakODRLinkage:
    case llvm::GlobalValue::CommonLinkage:
    {
        // We need to alias GV with NewGV offset by sizeof(EFFECTIVE_META).
        // Unfortunately LLVM does not support global aliases to ConstExprs,
        // so we use inline asm instead:
        std::string Asm(".globl ");
        Asm += GV.getName();
        Asm += '\n';
        Asm += ".set ";
        Asm += GV.getName();
        Asm += ", ";
        Asm += NewGV->getName();
        Asm += '+';
        Asm += std::to_string(sizeof(EFFECTIVE_META));
        M.appendModuleInlineAsm(Asm);
        break;
    }
    default:
        break;
    }
}

static EFFECTIVE_NOINLINE void replaceGlobals(llvm::Module &M, TypeInfo &tInfo)
{
    std::vector<llvm::GlobalVariable *> Dels;
    for (auto &GV: M.getGlobalList())
        replaceGlobal(M, GV, tInfo, Dels);
    for (auto GV: Dels)
        GV->eraseFromParent();
}

/*****************************************************************************/
/* STRIP METADATA                                                            */
/*****************************************************************************/

/*
 * Strip all of the effectivesan LLVM metadata.
 */
static EFFECTIVE_NOINLINE void stripMetaData(llvm::Module &M)
{
    for (auto &GV: M.getGlobalList())
        GV.setMetadata("effectiveSan", nullptr);
    for (auto &F: M)
    {
        F.setMetadata("effectiveSanArgs", nullptr);
        for (auto &BB: F)
        {
            for (auto &I: BB)
            {
                I.setMetadata("effectiveSan", nullptr);
                I.setMetadata("effectiveSanCookieSize", nullptr);
            }
        }
    }
}

/*****************************************************************************/
/* INSTRUMENTATION SUPPORT FUNCTIONS                                         */
/*****************************************************************************/

static EFFECTIVE_NOINLINE void emitInstrumentationFunctions(llvm::Module &M)
{
    llvm::Function *F = nullptr;

    // Note: Although these functions may access memory and throw, they are
    //       intended to be treated as "pure" and can be optimized as such.
    F = M.getFunction("effective_type_check");
    if (F != nullptr)
    {
        F->setDoesNotThrow();
        F->setDoesNotAccessMemory();
    }
    F = M.getFunction("effective_get_bounds");
    if (F != nullptr)
    {
        F->setDoesNotThrow();
        F->setDoesNotAccessMemory();
    }

    F = M.getFunction("effective_bounds_check");
#ifdef EFFECTIVE_FLAG_DEBUG
    bool debug = true;
#else
    bool debug = false;
#endif
    if (F != nullptr && !debug)
    {
        auto i = F->getArgumentList().begin();
        llvm::Value *Bounds = &*i; ++i;
        llvm::Value *Ptr = &*i; ++i;
        llvm::Value *LB = &*i; ++i;
        llvm::Value *UB = &*i;

        llvm::BasicBlock *Entry  = llvm::BasicBlock::Create(M.getContext(),
            "", F);
        llvm::BasicBlock *Return = llvm::BasicBlock::Create(M.getContext(),
            "", F);
        llvm::BasicBlock *Error  = llvm::BasicBlock::Create(M.getContext(),
            "", F);

        llvm::Value *Bounds0 = Bounds;
        {
            llvm::IRBuilder<> builder(Entry);
#ifdef EFFECTIVE_FLAG_PROFILE
            llvm::Value *Counter =
                M.getOrInsertGlobal("effective_num_bounds_checks",
                builder.getInt64Ty());
            builder.CreateAtomicRMW(llvm::AtomicRMWInst::Add, Counter,
                builder.getInt64(1),
                llvm::AtomicOrdering::SequentiallyConsistent);
#endif  /* EFFECTIVE_FLAG_PROFILE */
            llvm::Value *IPtr =
                builder.CreatePtrToInt(Ptr, builder.getInt64Ty());
            llvm::Value *Ptrs = llvm::UndefValue::get(BoundsTy);
            Ptrs = builder.CreateInsertElement(Ptrs, IPtr,
                builder.getInt32(0));
            Ptrs = builder.CreateInsertElement(Ptrs, IPtr,
                builder.getInt32(1));
            llvm::Value *Sizes = llvm::UndefValue::get(BoundsTy);
            LB = builder.CreateAdd(LB, builder.getInt64(1));
            Sizes = builder.CreateInsertElement(Sizes, LB,
                builder.getInt32(0));
            Sizes = builder.CreateInsertElement(Sizes, UB,
                builder.getInt32(1));
            Bounds = builder.CreateSub(Bounds, Sizes);
            llvm::Value *Cmp = builder.CreateICmpSGT(Ptrs, Bounds);
            Cmp = builder.CreateSExt(Cmp, BoundsTy);
            llvm::Type *Int8x16Ty = llvm::VectorType::get(builder.getInt8Ty(),
                16);
            Cmp = builder.CreateBitCast(Cmp, Int8x16Ty);
            llvm::Intrinsic::ID Id =
                llvm::Intrinsic::getIntrinsicForGCCBuiltin("x86",
                    "__builtin_ia32_pmovmskb128");
            llvm::Function *I = llvm::Intrinsic::getDeclaration(&M, Id);
            llvm::Value *Mask = builder.CreateCall(I, {Cmp});
            Cmp = builder.CreateICmpEQ(Mask, builder.getInt32(0x00FF));
            llvm::MDBuilder mdBuilder(M.getContext());
            llvm::MDNode *Weights =
                mdBuilder.createBranchWeights(2000000000, 1);
            builder.CreateCondBr(Cmp, Return, Error, Weights);
        }
        {
            llvm::IRBuilder<> builder(Return);
            builder.CreateRetVoid();
        }
        {
            llvm::IRBuilder<> builder(Error);
#ifndef EFFECTIVE_FLAG_COUNT
            llvm::Value *Size = builder.CreateSub(UB, LB);
            Size = builder.CreateAdd(Size, builder.getInt64(1));
            llvm::Constant *BoundsErr = M.getOrInsertFunction(
                "effective_bounds_error", builder.getVoidTy(),
                BoundsTy, builder.getInt8PtrTy(), builder.getInt64Ty(),
                nullptr);
            builder.CreateCall(BoundsErr, {Bounds0, Ptr, Size});
#else   /* EFFECTIVE_FLAG_COUNT */
            llvm::Value *CountPtr = M.getOrInsertGlobal(
                "effective_num_bounds_errors", builder.getInt64Ty());
#ifdef EFFECTIVE_FLAG_SINGLE_THREADED
            llvm::Value *Count = builder.CreateAlignedLoad(CountPtr,
                sizeof(size_t));
            Count = builder.CreateAdd(Count, builder.getInt64(1));
            builder.CreateAlignedStore(Count, CountPtr, sizeof(size_t));
#else   /* EFFECTIVE_FLAG_SINGLE_THREADED */
            builder.CreateAtomicRMW(llvm::AtomicRMWInst::Add, CountPtr,
                builder.getInt64(1),
                llvm::AtomicOrdering::SequentiallyConsistent);
#endif  /* EFFECTIVE_FLAG_SINGLE_THREADED */
#endif  /* EFFECTIVE_FLAG_COUNT */
#ifndef EFFECTIVE_FLAG_FATAL
            builder.CreateRetVoid();
#else   /* EFFECTIVE_FLAG_FATAL */
            if (auto F = llvm::dyn_cast<llvm::Function>(BoundsErr))
                F->setDoesNotReturn();
            builder.CreateUnreachable();
#endif  /* EFFECTIVE_FLAG_FATAL */
        }
        F->addFnAttr(llvm::Attribute::AlwaysInline);
        F->setDoesNotThrow();
        F->setLinkage(llvm::GlobalValue::InternalLinkage);
    }

    F = M.getFunction("effective_bounds_narrow");
    if (F != nullptr)
    {
        auto i = F->getArgumentList().begin();
        llvm::Value *BoundsA = &*i; ++i;
        llvm::Value *BoundsB = &*i;

        llvm::BasicBlock *Entry  = llvm::BasicBlock::Create(M.getContext(),
            "", F);
        llvm::IRBuilder<> builder(Entry);
        llvm::Value *Cmp = builder.CreateICmpSGT(BoundsA, BoundsB);
        Cmp = builder.CreateSExt(Cmp, BoundsTy);
        llvm::Value *Mask = M.getOrInsertGlobal("EFFECTIVE_BOUNDS_NEG_1_0",
            BoundsTy);
        Mask = builder.CreateAlignedLoad(Mask, 16);
        Cmp = builder.CreateXor(Cmp, Mask);
        llvm::Type *Int8x16Ty = llvm::VectorType::get(builder.getInt8Ty(), 16);
        BoundsA = builder.CreateBitCast(BoundsA, Int8x16Ty);
        BoundsB = builder.CreateBitCast(BoundsB, Int8x16Ty);
        Cmp = builder.CreateBitCast(Cmp, Int8x16Ty);
        llvm::Intrinsic::ID Id = llvm::Intrinsic::getIntrinsicForGCCBuiltin(
            "x86", "__builtin_ia32_pblendvb128");
        llvm::Function *I = llvm::Intrinsic::getDeclaration(&M, Id);
        llvm::Value *Bounds = builder.CreateCall(I, {BoundsA, BoundsB, Cmp});
        Bounds = builder.CreateBitCast(Bounds, BoundsTy);
        builder.CreateRet(Bounds);

        F->addFnAttr(llvm::Attribute::AlwaysInline);
        F->setDoesNotThrow();
        F->setLinkage(llvm::GlobalValue::InternalLinkage);
    }

    F = M.getFunction("lowfat_stack_mirror_2");
    if (F != nullptr)
    {
        auto i = F->getArgumentList().begin();
        llvm::Value *Ptr = &*i; ++i;
        llvm::Value *Offset = &*i;

        llvm::BasicBlock *Entry = llvm::BasicBlock::Create(M.getContext(),
            "", F);
        llvm::IRBuilder<> builder(Entry);
        llvm::Value *IPtr = builder.CreatePtrToInt(Ptr, builder.getInt64Ty());
        IPtr = builder.CreateAdd(IPtr, Offset);
        Ptr = builder.CreateIntToPtr(IPtr, builder.getInt8PtrTy());
        builder.CreateRet(Ptr);

        F->addFnAttr(llvm::Attribute::AlwaysInline);
        F->setDoesNotThrow();
        F->setLinkage(llvm::GlobalValue::InternalLinkage);
    }
}

/*****************************************************************************/
/* LLVM INTERFACE                                                            */
/*****************************************************************************/

namespace
{

/*
 * EffectiveSan LLVM pass.
 */
struct EffectiveSan : public llvm::ModulePass
{
    static char ID;

    EffectiveSan() : ModulePass(ID)
    {

    }

    virtual bool runOnModule(llvm::Module &M)
    {
        static bool runOnce = false;
        if (runOnce)
            EFFECTIVE_FATAL_ERROR("invoked twice");
        runOnce = true;

        if (getenv("EFFECTIVE_DEBUG") != nullptr)
            option_debug = true;
        if (option_debug)
        {
            fprintf(stderr, "       __  __           _   _           ____\n");
            fprintf(stderr, "  ___ / _|/ _| ___  ___| |_(_)_   _____/ ___|  __ _ _ __\n");
            fprintf(stderr, " / _ \\ |_| |_ / _ \\/ __| __| \\ \\ / / _ \\___ \\ / _` | '_ \\\n");
            fprintf(stderr, "|  __/  _|  _|  __/ (__| |_| |\\ V /  __/___) | (_| | | | |\n");
            fprintf(stderr, " \\___|_| |_|  \\___|\\___|\\__|_| \\_/ \\___|____/ \\__,_|_| |_|\n");
            fputc('\n', stderr);
        }

        if (option_blacklist != "-")
        {
            std::vector<std::string> Paths;
            Paths.push_back(option_blacklist);
            std::string err;
            Blacklist = llvm::SpecialCaseList::create(Paths, err);
        }

        DiagnosticInfoEffectiveSan::init();

        if (option_debug)
        {
            std::string outName(M.getName());
            outName += ".effective.in.ll";
            std::error_code EC;
            llvm::raw_fd_ostream out(outName.c_str(), EC,
                llvm::sys::fs::F_None);
            M.print(out, nullptr);
        }

        Module = &M;
        llvm::LLVMContext &Cxt = M.getContext();

        /*
         * Generate EffectiveSan meta data types and constants.
         */
        BoundsTy = llvm::VectorType::get(llvm::Type::getInt64Ty(Cxt), 2);
        InfoEntryTy = llvm::StructType::create(Cxt, "EFFECTIVE_INFO_ENTRY");
        InfoTy = makeTypeInfoType(M, 0);
        EntryTy = llvm::StructType::create(Cxt, "EFFECTIVE_ENTRY");
        TypeTy = makeTypeMetaType(M, 0);
        std::vector<llvm::Type *> Fields;
        Fields.push_back(llvm::Type::getInt64Ty(Cxt));      /* type */
        Fields.push_back(llvm::Type::getInt64Ty(Cxt));      /* _pad */
        Fields.push_back(BoundsTy);                         /* bounds */
        EntryTy->setBody(Fields, false);
        Fields.clear();
        Fields.push_back(InfoTy->getPointerTo());           /* type */
        Fields.push_back(llvm::Type::getInt32Ty(Cxt));      /* flags */
        Fields.push_back(llvm::Type::getInt64Ty(Cxt));      /* lb */
        Fields.push_back(llvm::Type::getInt64Ty(Cxt));      /* ub */
        InfoEntryTy->setBody(Fields, false);
        std::vector<llvm::Constant *> Elems;
        Elems.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt), 
            EFFECTIVE_ENTRY_EMPTY_HASH));
        Elems.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt),
            0));
        Elems.push_back(llvm::ConstantVector::get({
            llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt), 0),
            llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt), 0)}));
        EmptyEntry = llvm::ConstantStruct::get(EntryTy, Elems);
        ObjMetaTy = llvm::StructType::get(Cxt, /*isPacked=*/true);
        ObjMetaTy->setName("EFFECTIVE_META");
        Fields.clear();
        Fields.push_back(TypeTy->getPointerTo());           /* type */
        Fields.push_back(llvm::Type::getInt64Ty(Cxt));      /* size */
        ObjMetaTy->setBody(Fields, false);
        llvm::DebugInfoFinder DI;
        DI.processModule(M);

        TypeInfo tInfo;
        llvm::DIBuilder builder(M);
        Int8Ty = builder.createBasicType("char", CHAR_BIT,
            llvm::dwarf::DW_ATE_signed_char);
        Int16Ty = builder.createBasicType("short", 2 * CHAR_BIT,
            llvm::dwarf::DW_ATE_signed);
        Int32Ty = builder.createBasicType("int", 4 * CHAR_BIT,
            llvm::dwarf::DW_ATE_signed);
        Int64Ty = builder.createBasicType("long long int", 8 * CHAR_BIT,
            llvm::dwarf::DW_ATE_signed);
        Int128Ty = builder.createBasicType("__int128", 16 * CHAR_BIT,
            llvm::dwarf::DW_ATE_signed);
        Int8TyMeta = compileType(M, nullptr, tInfo).typeMeta;
        Int8PtrTy = builder.createPointerType(Int8Ty, sizeof(void *)*CHAR_BIT);
        BoundsNonFat = llvm::ConstantVector::get({
            llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt), 0),
            llvm::ConstantInt::get(llvm::Type::getInt64Ty(Cxt), INTPTR_MAX)});

        /*
         * Main instrumentation loop:
         */
        for (auto &F: M)
        {
            if (F.isDeclaration())
                continue;
            if (isBlacklisted("fun", F.getName()))
                continue;
            CheckInfo cInfo;
            std::set<llvm::Instruction *> Ignore;

            /*
             * Step #1: Replace malloc() with typed version:
             */
            replaceMallocs(M, F, tInfo, cInfo);

            /*
             * Step #2: Replace allocas with typed version:
             */
            replaceAllocas(M, F, tInfo, cInfo, Ignore);

            /*
             * Step #3: Do bounds-check/type-check instrumentation:
             */
            BoundsCheckInfo bcInfo;
            findPointersForBoundsCheck(M, F, bcInfo, cInfo, Ignore);
            optimizeBoundsChecks(M, F, cInfo, bcInfo);
            BoundsInfo bInfo;
            for (auto &Entry: bcInfo)
            {
                std::vector<BoundsCheckEntry> Checks = Entry.second;
                for (auto &Check: Checks)
                    instrumentBoundsCheck(M, F, Check, tInfo, cInfo, bInfo);
            }
        }

        /*
         * Step #4: Replace globals with typed version:
         */
        replaceGlobals(M, tInfo);

        /*
         * Strip metadata.
         */
        stripMetaData(M);

        /*
         * Step #6: Emit instrumentation functions.
         */
        emitInstrumentationFunctions(M);

        /*
         * Clean-up
         */
        metaCache.clear();
        infoCache.clear();

        if (option_debug)
        {
            std::string outName(M.getName());
            outName += ".effective.out.ll";
            std::error_code EC;
            llvm::raw_fd_ostream out(outName.c_str(), EC,
                llvm::sys::fs::F_None);
            M.print(out, nullptr);
        }

        return true;
    }
};

}

/*
 * LLVM pass boilerplate.
 */
char EffectiveSan::ID = 0;

static llvm::RegisterPass<EffectiveSan> X("effectivesan", "EffectiveSan pass");

namespace llvm
{
    ModulePass *createEffectiveSanPass()
    {
        return new EffectiveSan();
    }
}

