CXX=../install/bin/clang++

Test: export EFFECTIVE_DEBUG=1
Test: Test.cpp
	$(CXX) -mcmodel=large -fPIC -std=c++11 -fsanitize=effective \
        -O2 -c Shared.cpp
	$(CXX) -shared -o libShared.so Shared.o
	$(CXX) -std=c++11 -fsanitize=effective \
        -mllvm -effective-no-escapes -mllvm -effective-warnings \
        -mllvm -effective-blacklist -mllvm $(PWD)/effective.blacklist \
        -O2 -o Test Test.cpp -L. -lShared -Wl,-rpath=$(PWD)

Example: Example.cpp
	$(CXX) -std=c++11 -fsanitize=effective \
        -mllvm -effective-no-escapes \
        -O2 -o Example Example.cpp

Hijack: Hijack.cpp
	$(CXX) -std=c++11 -fsanitize=effective \
        -mllvm -effective-no-escapes \
        -O2 -o Hijack Hijack.cpp
clean:
	rm -rf Test a.out *.ll

