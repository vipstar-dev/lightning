#ifndef LIGHTNING_BITCOIN_BLOCK_H
#define LIGHTNING_BITCOIN_BLOCK_H
#include "config.h"
#include "bitcoin/shadouble.h"
#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

struct chainparams;

struct bitcoin_blkid {
	struct sha256_double shad;
};
/* Define bitcoin_blkid_eq (no padding) */
STRUCTEQ_DEF(bitcoin_blkid, 0, shad.sha.u);
struct bitcoin_block_hdr {
	le32 version;
	struct bitcoin_blkid prev_hash;
	struct sha256_double merkle_hash;
	le32 timestamp;
	le32 target;
	le32 nonce;
};

struct elements_block_proof {
	u8 *challenge;
	u8 *solution;
};

struct elements_block_hdr {
	u32 block_height;
	struct elements_block_proof proof;
};

struct qtum_block_hdr {
	u32 block_height;
	struct sha256_double hashStateRoot; // qtum
	struct sha256_double hashUTXORoot; //  qtum

	struct sha256_double prev_stake_hash;
	le32 prev_stake_n;

	u8 *vchSig;
};

struct bitcoin_block {
	struct bitcoin_block_hdr hdr;
	struct elements_block_hdr *elements_hdr;
	struct qtum_block_hdr *qtum_hdr;
	/* tal_count shows now many */
	struct bitcoin_tx **tx;
};

struct bitcoin_block *
bitcoin_block_from_hex(const tal_t *ctx, const struct chainparams *chainparams,
		       const char *hex, size_t hexlen);

/* Compute the double SHA block ID from the block header. */
void bitcoin_block_blkid(const struct bitcoin_block *block,
			 struct bitcoin_blkid *out);

/* Parse hex string to get blockid (reversed, a-la bitcoind). */
bool bitcoin_blkid_from_hex(const char *hexstr, size_t hexstr_len,
			    struct bitcoin_blkid *blockid);

/* Get hex string of blockid (reversed, a-la bitcoind). */
bool bitcoin_blkid_to_hex(const struct bitcoin_blkid *blockid,
			  char *hexstr, size_t hexstr_len);

void get_header(const u8 **p, size_t *len, struct bitcoin_block_hdr *hdr);

void sha256_header(struct sha256_double *shadouble, const struct bitcoin_block_hdr *hdr);
#endif /* LIGHTNING_BITCOIN_BLOCK_H */
