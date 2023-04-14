#include <iostream>
#include <stdint.h>
#include <stdlib.h>
using namespace std;

struct A{
    int a_val;
    char c;
    double d;
}__attribute__ ((packed));

struct B{
    int b_val;
    int a_val;
} __attribute__ ((packed));

struct C{
    double c_val;
    double d_val;
}__attribute__ ((packed));

int main(){
    uint8_t* buf  = (uint8_t*) malloc(sizeof(A) + sizeof(B) + sizeof(C));
    A* a = (A*) buf;
    B* b = (B*) (buf + sizeof(A));
    C* c = (C*) (buf + sizeof(A) + sizeof(B));
    a->a_val = 1;
    a->c = 'a';
    a->d = 1.0;
    b->b_val = 2;
    b->a_val = 3;
    c->c_val = 4.0;
    c->d_val = 5.0;
    cout << "a: " << a->a_val << " " << a->c << " " << a->d << endl;
    cout << "b: " << b->b_val << " " << b->a_val << endl;
    cout << "c: " << c->c_val << " " << c->d_val << endl;
    A aa;
    memcpy(&aa, buf, sizeof(A));
    cout << "aa: " << aa.a_val << " " << aa.c << " " << aa.d << endl;
    free(buf);
    return 0;
}
