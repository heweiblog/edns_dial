#ifndef DIAL_HASH_H

#define DIAL_HASH_H




typedef struct hash_info {
	int num;	
	DIAL_LIST_HEAD *tab;
	//int (*hash_key)(void *,int);
	int (*hash_key)(const char *,int);
	void (*hash_add)(struct hash_info *,const char*,DIAL_LIST_NODE *);
	void (*hash_del)(struct hash_info *,DIAL_LIST_NODE *);
	void (*hash_clear)(struct hash_info *);
	DIAL_LIST_NODE *(*hash_search)(struct hash_info *,const char *);
	
} hash_info_t;

int
hash_init_healthgroup(hash_info_t *hash,
	int num);
int
hash_init_nginxgroup(hash_info_t *hash,
	int num);
int
hash_init_healthpolicy(hash_info_t *hash,
	int num);
void 
hash_destory_healthgroup(hash_info_t *hash);
void 
hash_destory_nginxgroup(hash_info_t *hash);
void 
hash_destory_healthpolicy(hash_info_t *hash);

int hash_key(const char *str,int size);

#endif








