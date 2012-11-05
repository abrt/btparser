// gcc -fno-inline -o null_dereference null_dereference.c
void a(void)
{
    int *p = 0;
    *p = 10;
}

void b(int i)
{
    if (i == 0)
        a();
    else
        b(i-1);
}

void c(void)
{
    b(1);
}

int main(int argc, char** argv)
{
    c();
    return 0;
}
