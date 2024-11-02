struct bit_vector{
    unsigned int bits[4];
};

void 
init_bit_vector (struct bit_vector* v);

int 
find_min (struct bit_vector *v);

void 
set_vector(struct bit_vector *v, int pos);

void 
unset_vector(struct bit_vector *v, int pos);