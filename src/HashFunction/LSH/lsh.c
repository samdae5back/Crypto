#include "lsh_internal.h"

#include "Util/Bit/bit_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/Endian/endian_internal.h"

#include <string.h>

/* LSH-256 and LSH-512 use the shared endian-independent byte helpers. */



#define LSH256_NUM_ROUNDS 26
#define LSH512_NUM_ROUNDS 28
#define LSH_NUM_WORDS 16

static const unsigned char tau[LSH_NUM_WORDS] = {
	3, 2, 0, 1, 7, 4, 5, 6, 11, 10, 8, 9, 15, 12, 13, 14};

static const unsigned char gamma32[8] = {0, 8, 16, 24, 24, 16, 8, 0};
static const unsigned char gamma64[8] = {0, 16, 32, 48, 8, 24, 40, 56};
static const unsigned char delta[LSH_NUM_WORDS] = {
	6, 4, 5, 7, 12, 15, 14, 13, 2, 0, 1, 3, 8, 11, 10, 9};

static const uint32_t SC32[LSH256_NUM_ROUNDS * 8] = {
	0x917caf90, 0x6c1b10a2, 0x6f352943, 0xcf778243,
	0x2ceb7472, 0x29e96ff2, 0x8a9ba428, 0x2eeb2642,
	0x0e2c4021, 0x872bb30e, 0xa45e6cb2, 0x46f9c612,
	0x185fe69e, 0x1359621b, 0x263fccb2, 0x1a116870,
	0x3a6c612f, 0xb2dec195, 0x02cb1f56, 0x40bfd858,
	0x784684b6, 0x6cbb7d2e, 0x660c7ed8, 0x2b79d88a,
	0xa6cd9069, 0x91a05747, 0xcdea7558, 0x00983098,
	0xbecb3b2e, 0x2838ab9a, 0x728b573e, 0xa55262b5,
	0x745dfa0f, 0x31f79ed8, 0xb85fce25, 0x98c8c898,
	0x8a0669ec, 0x60e445c2, 0xfde295b0, 0xf7b5185a,
	0xd2580983, 0x29967709, 0x182df3dd, 0x61916130,
	0x90705676, 0x452a0822, 0xe07846ad, 0xaccd7351,
	0x2a618d55, 0xc00d8032, 0x4621d0f5, 0xf2f29191,
	0x00c6cd06, 0x6f322a67, 0x58bef48d, 0x7a40c4fd,
	0x8beee27f, 0xcd8db2f2, 0x67f2c63b, 0xe5842383,
	0xc793d306, 0xa15c91d6, 0x17b381e5, 0xbb05c277,
	0x7ad1620a, 0x5b40a5bf, 0x5ab901a2, 0x69a7a768,
	0x5b66d9cd, 0xfdee6877, 0xcb3566fc, 0xc0c83a32,
	0x4c336c84, 0x9be6651a, 0x13baa3fc, 0x114f0fd1,
	0xc240a728, 0xec56e074, 0x009c63c7, 0x89026cf2,
	0x7f9ff0d0, 0x824b7fb5, 0xce5ea00f, 0x605ee0e2,
	0x02e7cfea, 0x43375560, 0x9d002ac7, 0x8b6f5f7b,
	0x1f90c14f, 0xcdcb3537, 0x2cfeafdd, 0xbf3fc342,
	0xeab7b9ec, 0x7a8cb5a3, 0x9d2af264, 0xfacedb06,
	0xb052106e, 0x99006d04, 0x2bae8d09, 0xff030601,
	0xa271a6d6, 0x0742591d, 0xc81d5701, 0xc9a9e200,
	0x02627f1e, 0x996d719d, 0xda3b9634, 0x02090800,
	0x14187d78, 0x499b7624, 0xe57458c9, 0x738be2c9,
	0x64e19d20, 0x06df0f36, 0x15d1cb0e, 0x0b110802,
	0x2c95f58c, 0xe5119a6d, 0x59cd22ae, 0xff6eac3c,
	0x467ebd84, 0xe5ee453c, 0xe79cd923, 0x1c190a0d,
	0xc28b81b8, 0xf6ac0852, 0x26efd107, 0x6e1ae93b,
	0xc53c41ca, 0xd4338221, 0x8475fd0a, 0x35231729,
	0x4e0d3a7a, 0xa2b45b48, 0x16c0d82d, 0x890424a9,
	0x017e0c8f, 0x07b5a3f5, 0xfa73078e, 0x583a405e,
	0x5b47b4c8, 0x570fa3ea, 0xd7990543, 0x8d28ce32,
	0x7f8a9b90, 0xbd5998fc, 0x6d7a9688, 0x927a9eb6,
	0xa2fc7d23, 0x66b38e41, 0x709e491a, 0xb5f700bf,
	0x0a262c0f, 0x16f295b9, 0xe8111ef5, 0x0d195548,
	0x9f79a0c5, 0x1a41cfa7, 0x0ee7638a, 0xacf7c074,
	0x30523b19, 0x09884ecf, 0xf93014dd, 0x266e9d55,
	0x191a6664, 0x5c1176c1, 0xf64aed98, 0xa4b83520,
	0x828d5449, 0x91d71dd8, 0x2944f2d6, 0x950bf27b,
	0x3380ca7d, 0x6d88381d, 0x4138868e, 0x5ced55c4,
	0x0fe19dcb, 0x68f4f669, 0x6e37c8ff, 0xa0fe6e10,
	0xb44b47b0, 0xf5c0558a, 0x79bf14cf, 0x4a431a20,
	0xf17f68da, 0x5deb5fd1, 0xa600c86d, 0x9f6c7eb0,
	0xff92f864, 0xb615e07f, 0x38d3e448, 0x8d5d3a6a,
	0x70e843cb, 0x494b312e, 0xa6c93613, 0x0beb2f4f,
	0x928b5d63, 0xcbf66035, 0x0cb82c80, 0xea97a4f7,
	0x592c0f3b, 0x947c5f77, 0x6fff49b9, 0xf71a7e5a,
	0x1de8c0f5, 0xc2569600, 0xc4e4ac8c, 0x823c9ce1
};

static const uint64_t SC64[LSH512_NUM_ROUNDS * 8] = {
	0x97884283c938982aULL, 0xba1fca93533e2355ULL,
	0xc519a2e87aeb1c03ULL, 0x9a0fc95462af17b1ULL,
	0xfc3dda8ab019a82bULL, 0x02825d079a895407ULL,
	0x79f2d0a7ee06a6f7ULL, 0xd76d15eed9fdf5feULL,
	0x1fcac64d01d0c2c1ULL, 0xd9ea5de69161790fULL,
	0xdebc8b6366071fc8ULL, 0xa9d91db711c6c94bULL,
	0x3a18653ac9c1d427ULL, 0x84df64a223dd5b09ULL,
	0x6cc37895f4ad9e70ULL, 0x448304c8d7f3f4d5ULL,
	0xea91134ed29383e0ULL, 0xc4484477f2da88e8ULL,
	0x9b47eec96d26e8a6ULL, 0x82f6d4c8d89014f4ULL,
	0x527da0048b95fb61ULL, 0x644406c60138648dULL,
	0x303c0e8aa24c0edcULL, 0xc787cda0cbe8ca19ULL,
	0x7ba46221661764caULL, 0x0c8cbc6acd6371acULL,
	0xe336b836940f8f41ULL, 0x79cb9da168a50976ULL,
	0xd01da49021915cb3ULL, 0xa84accc7399cf1f1ULL,
	0x6c4a992cee5aeb0cULL, 0x4f556e6cb4b2e3e0ULL,
	0x200683877d7c2f45ULL, 0x9949273830d51db8ULL,
	0x19eeeecaa39ed124ULL, 0x45693f0a0dae7fefULL,
	0xedc234b1b2ee1083ULL, 0xf3179400d68ee399ULL,
	0xb6e3c61b4945f778ULL, 0xa4c3db216796c42fULL,
	0x268a0b04f9ab7465ULL, 0xe2705f6905f2d651ULL,
	0x08ddb96e426ff53dULL, 0xaea84917bc2e6f34ULL,
	0xaff6e664a0fe9470ULL, 0x0aab94d765727d8cULL,
	0x9aa9e1648f3d702eULL, 0x689efc88fe5af3d3ULL,
	0xb0950ffea51fd98bULL, 0x52cfc86ef8c92833ULL,
	0xe69727b0b2653245ULL, 0x56f160d3ea9da3e2ULL,
	0xa6dd4b059f93051fULL, 0xb6406c3cd7f00996ULL,
	0x448b45f3ccad9ec8ULL, 0x079b8587594ec73bULL,
	0x45a50ea3c4f9653bULL, 0x22983767c1f15b85ULL,
	0x7dbed8631797782bULL, 0x485234be88418638ULL,
	0x842850a5329824c5ULL, 0xf6aca914c7f9a04cULL,
	0xcfd139c07a4c670cULL, 0xa3210ce0a8160242ULL,
	0xeab3b268be5ea080ULL, 0xbacf9f29b34ce0a7ULL,
	0x3c973b7aaf0fa3a8ULL, 0x9a86f346c9c7be80ULL,
	0xac78f5d7cabcea49ULL, 0xa355bddcc199ed42ULL,
	0xa10afa3ac6b373dbULL, 0xc42ded88be1844e5ULL,
	0x9e661b271cff216aULL, 0x8a6ec8dd002d8861ULL,
	0xd3d2b629beb34be4ULL, 0x217a3a1091863f1aULL,
	0x256ecda287a733f5ULL, 0xf9139a9e5b872fe5ULL,
	0xac0535017a274f7cULL, 0xf21b7646d65d2aa9ULL,
	0x048142441c208c08ULL, 0xf937a5dd2db5e9ebULL,
	0xa688dfe871ff30b7ULL, 0x9bb44aa217c5593bULL,
	0x943c702a2edb291aULL, 0x0cae38f9e2b715deULL,
	0xb13a367ba176cc28ULL, 0x0d91bd1d3387d49bULL,
	0x85c386603cac940cULL, 0x30dd830ae39fd5e4ULL,
	0x2f68c85a712fe85dULL, 0x4ffeecb9dd1e94d6ULL,
	0xd0ac9a590a0443aeULL, 0xbae732dc99ccf3eaULL,
	0xeb70b21d1842f4d9ULL, 0x9f4eda50bb5c6fa8ULL,
	0x4949e69ce940a091ULL, 0x0e608dee8375ba14ULL,
	0x983122cba118458cULL, 0x4eeba696fbb36b25ULL,
	0x7d46f3630e47f27eULL, 0xa21a0f7666c0dea4ULL,
	0x5c22cf355b37cec4ULL, 0xee292b0c17cc1847ULL,
	0x9330838629e131daULL, 0x6eee7c71f92fce22ULL,
	0xc953ee6cb95dd224ULL, 0x3a923d92af1e9073ULL,
	0xc43a5671563a70fbULL, 0xbc2985dd279f8346ULL,
	0x7ef2049093069320ULL, 0x17543723e3e46035ULL,
	0xc3b409b00b130c6dULL, 0x5d6aee6b28fdf090ULL,
	0x1d425b26172ff6edULL, 0xcccfd041cdaf03adULL,
	0xfe90c7c790ab6cbfULL, 0xe5af6304c722ca02ULL,
	0x70f695239999b39eULL, 0x6b8b5b07c844954cULL,
	0x77bdb9bb1e1f7a30ULL, 0xc859599426ee80edULL,
	0x5f9d813d4726e40aULL, 0x9ca0120f7cb2b179ULL,
	0x8f588f583c182cbdULL, 0x951267cbe9eccce7ULL,
	0x678bb8bd334d520eULL, 0xf6e662d00cd9e1b7ULL,
	0x357774d93d99aaa7ULL, 0x21b2edbb156f6eb5ULL,
	0xfd1ebe846e0aee69ULL, 0x3cb2218c2f642b15ULL,
	0xe7e7e7945444ea4cULL, 0xa77a33b5d6b9b47cULL,
	0xf34475f0809f6075ULL, 0xdd4932dce6bb99adULL,
	0xacec4e16d74451dcULL, 0xd4a0a8d084de23d6ULL,
	0x1bdd42f278f95866ULL, 0xeed3adbb938f4051ULL,
	0xcfcf7be8992f3733ULL, 0x21ade98c906e3123ULL,
	0x37ba66711fffd668ULL, 0x267c0fc3a255478aULL,
	0x993a64ee1b962e88ULL, 0x754979556301faaaULL,
	0xf920356b7251be81ULL, 0xc281694f22cf923fULL,
	0x9f4b6481c8666b02ULL, 0xcf97761cfe9f5444ULL,
	0xf220d7911fd63e9fULL, 0xa28bd365f79cd1b0ULL,
	0xd39f5309b1c4b721ULL, 0xbec2ceb864fca51fULL,
	0x1955a0ddc410407aULL, 0x43eab871f261d201ULL,
	0xeaafe64a2ed16da1ULL, 0x670d931b9df39913ULL,
	0x12f868b0f614de91ULL, 0x2e5f395d946e8252ULL,
	0x72f25cbb767bd8f4ULL, 0x8191871d61a1c4ddULL,
	0x6ef67ea1d450ba93ULL, 0x2ea32a645433d344ULL,
	0x9a963079003f0f8bULL, 0x74a0aeb9918cac7aULL,
	0x0b6119a70af36fa3ULL, 0x8d9896f202f0d480ULL,
	0x654f1831f254cd66ULL, 0x1318a47f0366a25eULL,
	0x65752076250b4e01ULL, 0xd1cd8eb888071772ULL,
	0x30c6a9793f4e9b25ULL, 0x154f684b1e3926eeULL,
	0x6c7ac0b1fe6312aeULL, 0x262f88f4f3c5550dULL,
	0xb4674a24472233cbULL, 0x2bbd23826a090071ULL,
	0xda95969b30594f66ULL, 0x9f5c47408f1e8a43ULL,
	0xf77022b88de9c055ULL, 0x64b7b36957601503ULL,
	0xe73b72b06175c11aULL, 0x55b87de8b91a6233ULL,
	0x1bb16e6b6955ff7fULL, 0xe8e0a5ec7309719cULL,
	0x702c31cb89a8b640ULL, 0xfba387cfada8cde2ULL,
	0x6792db4677aa164cULL, 0x1c6b1cc0b7751867ULL,
	0x22ae2311d736dc01ULL, 0x0e3666a1d37c9588ULL,
	0xcd1fd9d4bf557e9aULL, 0xc986925f7c7b0e84ULL,
	0x9c5dfd55325ef6b0ULL, 0x9f2b577d5676b0ddULL,
	0xfa6e21be21c062b3ULL, 0x8787dd782c8d7f83ULL,
	0xd0d134e90e12dd23ULL, 0x449d087550121d96ULL,
	0xecf9ae9414d41967ULL, 0x5018f1dbf789934dULL,
	0xfa5b52879155a74cULL, 0xca82d4d3cd278e7cULL,
	0x688fdfdfe22316adULL, 0x0f6555a4ba0d030aULL,
	0xa2061df720f000f3ULL, 0xe1a57dc5622fb3daULL,
	0xe6a842a8e8ed8153ULL, 0x690acdd3811ce09dULL,
	0x55adda18e6fcf446ULL, 0x4d57a8a0f4b60b46ULL,
	0xf86fbfc20539c415ULL, 0x74bafa5ec7100d19ULL,
	0xa824151810f0f495ULL, 0x8723432791e38ebbULL,
	0x8eeaeb91d66ed539ULL, 0x73d8a1549dfd7e06ULL,
	0x0387f2ffe3f13a9bULL, 0xa5004995aac15193ULL,
	0x682f81c73efdda0dULL, 0x2fb55925d71d268dULL,
	0xcc392d2901e58a3dULL, 0xaa666ab975724a42ULL
};

static const uint32_t iv_lsh_256_224[LSH_NUM_WORDS] = {
	0x068608D3, 0x62D8F7A7, 0xD76652AB, 0x4C600A43,
	0xBDC40AA8, 0x1ECA0B68, 0xDA1A89BE, 0x3147D354,
	0x707EB4F9, 0xF65B3862, 0x6B0B2ABE, 0x56B8EC0A,
	0xCF237286, 0xEE0D1727, 0x33636595, 0x8BB8D05F
};

static const uint32_t iv_lsh_256_256[LSH_NUM_WORDS] = {
	0x46A10F1F, 0xFDDCE486, 0xB41443A8, 0x198E6B9D,
	0x3304388D, 0xB0F5A3C7, 0xB36061C4, 0x7ADBD553,
	0x105D5378, 0x2F74DE54, 0x5C2F2D95, 0xF2553FBE,
	0x8051357A, 0x138668C8, 0x47AA4484, 0xE01AFB41
};

static const uint64_t iv_lsh_512_224[LSH_NUM_WORDS] = {
	0x0C401E9FE8813A55ULL, 0x4A5F446268FD3D35ULL,
	0xFF13E452334F612AULL, 0xF8227661037E354AULL,
	0xA5F223723C9CA29DULL, 0x95D965A11AED3979ULL,
	0x01E23835B9AB02CCULL, 0x52D49CBAD5B30616ULL,
	0x9E5C2027773F4ED3ULL, 0x66A5C8801925B701ULL,
	0x22BBC85B4C6779D9ULL, 0xC13171A42C559C23ULL,
	0x31E2B67D25BE3813ULL, 0xD522C4DEED8E4D83ULL,
	0xA79F5509B43FBAFEULL, 0xE00D2CD88B4B6C6AULL
};

static const uint64_t iv_lsh_512_256[LSH_NUM_WORDS] = {
	0x6DC57C33DF989423ULL, 0xD8EA7F6E8342C199ULL,
	0x76DF8356F8603AC4ULL, 0x40F1B44DE838223AULL,
	0x39FFE7CFC31484CDULL, 0x39C4326CC5281548ULL,
	0x8A2FF85A346045D8ULL, 0xFF202AA46DBDD61EULL,
	0xCF785B3CD5FCDB8BULL, 0x1F0323B64A8150BFULL,
	0xFF75D972F29EA355ULL, 0x2E567F30BF1CA9E1ULL,
	0xB596875BF8FF6DBAULL, 0xFCCA39B089EF4615ULL,
	0xECFF4017D020B4B6ULL, 0x7E77384C772ED802ULL
};

static const uint64_t iv_lsh_512_384[LSH_NUM_WORDS] = {
	0x53156A66292808F6ULL, 0xB2C4F362B204C2BCULL,
	0xB84B7213BFA05C4EULL, 0x976CEB7C1B299F73ULL,
	0xDF0CC63C0570AE97ULL, 0xDA4441BAA486CE3FULL,
	0x6559F5D9B5F2ACC2ULL, 0x22DACF19B4B52A16ULL,
	0xBBCDACEFDE80953AULL, 0xC9891A2879725B3EULL,
	0x7C9FE6330237E440ULL, 0xA30BA550553F7431ULL,
	0xBB08043FB34E3E30ULL, 0xA0DEC48D54618EADULL,
	0x150317267464BC57ULL, 0x32D1501FDE63DC93ULL
};

static const uint64_t iv_lsh_512_512[LSH_NUM_WORDS] = {
	0xADD50F3C7F07094EULL, 0xE3F3CEE8F9418A4FULL,
	0xB527ECDE5B3D0AE9ULL, 0x2EF6DEC68076F501ULL,
	0x8CB994CAE5ACA216ULL, 0xFBB9EAE4BBA48CC7ULL,
	0x650A526174725FEAULL, 0x1F9A61A73F8D8085ULL,
	0xB6607378173B539BULL, 0x1BC99853B0C0B9EDULL,
	0xDF727FC19B182D47ULL, 0xDBEF360CF893A457ULL,
	0x4981F5E570147E80ULL, 0xD00C4490CA7D3E30ULL,
	0x5D73940C0E4AE1ECULL, 0x894085E2EDB2D819ULL
};


static void lsh_wipe32(uint32_t *p, unsigned int words)
{
	volatile uint32_t *v = p;
	unsigned int i;
	for (i = 0; i < words; i++) v[i] = 0;
}

static void lsh_wipe64(uint64_t *p, unsigned int words)
{
	volatile uint64_t *v = p;
	unsigned int i;
	for (i = 0; i < words; i++) v[i] = 0;
}

static void LSH_256_224_Preprocess(unsigned char out[64])
{
	memcpy(out, iv_lsh_256_224, sizeof(iv_lsh_256_224));
}

static void LSH_256_256_Preprocess(unsigned char out[64])
{
	memcpy(out, iv_lsh_256_256, sizeof(iv_lsh_256_256));
}

static void LSH_512_224_Preprocess(unsigned char out[128])
{
	memcpy(out, iv_lsh_512_224, sizeof(iv_lsh_512_224));
}

static void LSH_512_256_Preprocess(unsigned char out[128])
{
	memcpy(out, iv_lsh_512_256, sizeof(iv_lsh_512_256));
}

static void LSH_512_384_Preprocess(unsigned char out[128])
{
	memcpy(out, iv_lsh_512_384, sizeof(iv_lsh_512_384));
}

static void LSH_512_512_Preprocess(unsigned char out[128])
{
	memcpy(out, iv_lsh_512_512, sizeof(iv_lsh_512_512));
}

static void LSH_256_CompressBlock(unsigned char in_out[64], const unsigned char in[128])
{
	uint32_t out[LSH_NUM_WORDS];
	uint32_t tmp[LSH_NUM_WORDS];
	uint32_t msgExp[LSH256_NUM_ROUNDS + 1][LSH_NUM_WORDS];
	int i, j;

	memcpy(out, in_out, sizeof(out));


	for (j = 0; j < LSH_NUM_WORDS; j++) {
		msgExp[0][j] = crypto_load32_le(in + 4 * j);
		msgExp[1][j] = crypto_load32_le(in + 4 * (LSH_NUM_WORDS + j));
	}
	for (i = 2; i <= LSH256_NUM_ROUNDS; i++) {
		for (j = 0; j < LSH_NUM_WORDS; j++) {

			msgExp[i][j] = msgExp[i - 1][j] + msgExp[i - 2][tau[j]];
		}
	}


	for (i = 0; i < LSH256_NUM_ROUNDS; i++) {
		// MsgAdd
		for (j = 0; j < LSH_NUM_WORDS; j++) out[j] ^= msgExp[i][j];
		// Mix_i
		for (j = 0; j < 8; j++) {
			out[j    ] += out[j + 8];
			out[j    ] = crypto_rotl32(out[j], (i & 0x1) ? 5 : 29);
			out[j    ] ^= SC32[i * 8 + j];
			out[j + 8] += out[j];
			out[j + 8] = crypto_rotl32(out[j + 8], (i & 0x1) ? 17 : 1);
			out[j    ] += out[j + 8];
			out[j + 8] = crypto_rotl32(out[j + 8], gamma32[j]);
		}
		// WordPerm
		for (j = 0; j < LSH_NUM_WORDS; j++) tmp[j] = out[delta[j]];
		for (j = 0; j < LSH_NUM_WORDS; j++) out[j] = tmp[j];
	}


	for (j = 0; j < LSH_NUM_WORDS; j++) out[j] ^= msgExp[LSH256_NUM_ROUNDS][j];

	memcpy(in_out, out, sizeof(out));

	lsh_wipe32(&msgExp[0][0], (LSH256_NUM_ROUNDS + 1) * LSH_NUM_WORDS);
	lsh_wipe32(tmp, LSH_NUM_WORDS);
	lsh_wipe32(out, LSH_NUM_WORDS);
}

static void LSH_512_CompressBlock(unsigned char in_out[128], const unsigned char in[256])
{
	uint64_t out[LSH_NUM_WORDS];
	uint64_t tmp[LSH_NUM_WORDS];
	uint64_t msgExp[LSH512_NUM_ROUNDS + 1][LSH_NUM_WORDS];
	int i, j;

	memcpy(out, in_out, sizeof(out));


	for (j = 0; j < LSH_NUM_WORDS; j++) {
		msgExp[0][j] = crypto_load64_le(in + 8 * j);
		msgExp[1][j] = crypto_load64_le(in + 8 * (LSH_NUM_WORDS + j));
	}
	for (i = 2; i <= LSH512_NUM_ROUNDS; i++) {
		for (j = 0; j < LSH_NUM_WORDS; j++) {

			msgExp[i][j] = msgExp[i - 1][j] + msgExp[i - 2][tau[j]];
		}
	}


	for (i = 0; i < LSH512_NUM_ROUNDS; i++) {
		// MsgAdd
		for (j = 0; j < LSH_NUM_WORDS; j++) out[j] ^= msgExp[i][j];
		// Mix_i
		for (j = 0; j < 8; j++) {
			out[j    ] += out[j + 8];
			out[j    ] = crypto_rotl64(out[j], (i & 0x1) ? 7 : 23);
			out[j    ] ^= SC64[i * 8 + j];
			out[j + 8] += out[j];
			out[j + 8] = crypto_rotl64(out[j + 8], (i & 0x1) ? 3 : 59);
			out[j    ] += out[j + 8];
			out[j + 8] = crypto_rotl64(out[j + 8], gamma64[j]);
		}
		// WordPerm
		for (j = 0; j < LSH_NUM_WORDS; j++) tmp[j] = out[delta[j]];
		for (j = 0; j < LSH_NUM_WORDS; j++) out[j] = tmp[j];
	}


	for (j = 0; j < LSH_NUM_WORDS; j++) out[j] ^= msgExp[LSH512_NUM_ROUNDS][j];

	memcpy(in_out, out, sizeof(out));

	lsh_wipe64(&msgExp[0][0], (LSH512_NUM_ROUNDS + 1) * LSH_NUM_WORDS);
	lsh_wipe64(tmp, LSH_NUM_WORDS);
	lsh_wipe64(out, LSH_NUM_WORDS);
}


static void lsh256_return(unsigned char *out, const unsigned char *in, unsigned int dlen)
{
	uint32_t l[8], r[8];
	unsigned int j;

	memcpy(l, in, sizeof(l));
	memcpy(r, in + 32, sizeof(r));

	for (j = 0; j < dlen / 4; j++) {
		crypto_store32_le(out + 4u * j, l[j] ^ r[j]);
	}

	lsh_wipe32(l, 8);
	lsh_wipe32(r, 8);
}

static void lsh512_return(unsigned char *out, const unsigned char *in, unsigned int dlen)
{
	uint64_t l[8], r[8];
	unsigned int j, full = dlen / 8;

	memcpy(l, in, sizeof(l));
	memcpy(r, in + 64, sizeof(r));

	for (j = 0; j < full; j++) {
		crypto_store64_le(out + 8u * j, l[j] ^ r[j]);
	}
	if (dlen % 8) {
		crypto_store32_le(out + 8u * full, (uint32_t)(l[full] ^ r[full]));
	}

	lsh_wipe64(l, 8);
	lsh_wipe64(r, 8);
}

static void LSH_256_224_Return(unsigned char out[28], const unsigned char in[64])
{
	lsh256_return(out, in, 28);
}

static void LSH_256_256_Return(unsigned char out[32], const unsigned char in[64])
{
	lsh256_return(out, in, 32);
}

static void LSH_512_224_Return(unsigned char out[28], const unsigned char in[128])
{
	lsh512_return(out, in, 28);
}

static void LSH_512_256_Return(unsigned char out[32], const unsigned char in[128])
{
	lsh512_return(out, in, 32);
}

static void LSH_512_384_Return(unsigned char out[48], const unsigned char in[128])
{
	lsh512_return(out, in, 48);
}

static void LSH_512_512_Return(unsigned char out[64], const unsigned char in[128])
{
	lsh512_return(out, in, 64);
}

CryptoError crypto_lsh_hash(
	uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
	const uint8_t *INPUT, size_t INPUT_LENGTH,
	AlgID ALG)
{
	unsigned char state[128];
	unsigned char block[256];
	size_t block_length;
	int use_lsh512;

	(void)OUTPUT_LENGTH;
	memset(state, 0, sizeof(state));
	switch (ALG) {
	case ALG_HASH_LSH_256_224:
		LSH_256_224_Preprocess(state);
		block_length = 128u;
		use_lsh512 = 0;
		break;
	case ALG_HASH_LSH_256_256:
		LSH_256_256_Preprocess(state);
		block_length = 128u;
		use_lsh512 = 0;
		break;
	case ALG_HASH_LSH_512_224:
		LSH_512_224_Preprocess(state);
		block_length = 256u;
		use_lsh512 = 1;
		break;
	case ALG_HASH_LSH_512_256:
		LSH_512_256_Preprocess(state);
		block_length = 256u;
		use_lsh512 = 1;
		break;
	case ALG_HASH_LSH_512_384:
		LSH_512_384_Preprocess(state);
		block_length = 256u;
		use_lsh512 = 1;
		break;
	case ALG_HASH_LSH_512_512:
		LSH_512_512_Preprocess(state);
		block_length = 256u;
		use_lsh512 = 1;
		break;
	default:
		crypto_zeroize(state, sizeof(state));
		return CRYPTO_ERROR_INVALID_ALG_ID;
	}

	while (INPUT_LENGTH >= block_length) {
		if (use_lsh512) {
			LSH_512_CompressBlock(state, INPUT);
		} else {
			LSH_256_CompressBlock(state, INPUT);
		}
		INPUT += block_length;
		INPUT_LENGTH -= block_length;
	}

	memset(block, 0, sizeof(block));
	if (INPUT_LENGTH != 0u) {
		memcpy(block, INPUT, INPUT_LENGTH);
	}
	block[INPUT_LENGTH] = 0x80u;
	if (use_lsh512) {
		LSH_512_CompressBlock(state, block);
	} else {
		LSH_256_CompressBlock(state, block);
	}

	switch (ALG) {
	case ALG_HASH_LSH_256_224:
		LSH_256_224_Return(OUTPUT, state);
		break;
	case ALG_HASH_LSH_256_256:
		LSH_256_256_Return(OUTPUT, state);
		break;
	case ALG_HASH_LSH_512_224:
		LSH_512_224_Return(OUTPUT, state);
		break;
	case ALG_HASH_LSH_512_256:
		LSH_512_256_Return(OUTPUT, state);
		break;
	case ALG_HASH_LSH_512_384:
		LSH_512_384_Return(OUTPUT, state);
		break;
	default:
		LSH_512_512_Return(OUTPUT, state);
		break;
	}

	crypto_zeroize(block, sizeof(block));
	crypto_zeroize(state, sizeof(state));
	return CRYPTO_SUCCESS;
}
