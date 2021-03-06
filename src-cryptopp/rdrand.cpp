// rdrand.cpp - written and placed in public domain by Jeffrey Walton and Uri Blumenthal.
//              Copyright assigned to Crypto++ project.

#include "pch.h"
#include "config.h"
#include "cryptlib.h"
#include "secblock.h"
#include "rdrand.h"
#include "cpu.h"

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4100)
#endif

// This file (and friends) provides both RDRAND and RDSEED, but its somewhat
//   experimental. They were added at Crypto++ 5.6.3. At compile time, it
//   indirectly uses CRYPTOPP_BOOL_{X86|X32|X64} (via CRYPTOPP_CPUID_AVAILABLE)
//   to select an implementation or "throw NotImplemented". At runtime, the
//   class uses the result of CPUID to determine if RDRAND or RDSEED are
//   available. A lazy throw strategy is used in case the CPU does not support
//   the instruction. I.e., the throw is deferred until GenerateBlock is called.

// Here's the naming convention for the functions....
//   MSC = Microsoft Compiler (and compatibles)
//   GCC = GNU Compiler (and compatibles)
//   ALL = MSC and GCC (and compatibles)
//   RRA = RDRAND, Assembly
//   RSA = RDSEED, Assembly
//   RRI = RDRAND, Intrinsic
//   RSA = RDSEED, Intrinsic

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

// For Linux, install NASM, run rdrand-nasm.asm, add the apppropriate
// object file to the Makefile's LIBOBJS (rdrand-x{86|32|64}.o). After
// that, define these. They are not enabled by default because they
// are not easy to cut-in in the Makefile.

#if 0
#define NASM_RDRAND_ASM_AVAILABLE 1
#define NASM_RDSEED_ASM_AVAILABLE 1
#endif

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

// According to Wei, CRYPTOPP_DISABLE_ASM is a failsafe due to the assembler.
//   We sidestep it because it does not limit us. The assembler does not limit
//   us because we emit out own byte codes as needed. To diasble RDRAND or
//    RDSEED, set CRYPTOPP_BOOL_RDRAND_ASM or CRYPTOPP_BOOL_RDSEED_ASM to 0.
#ifndef CRYPTOPP_CPUID_AVAILABLE
# if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
#  define CRYPTOPP_CPUID_AVAILABLE
# endif
#endif

#if defined(CRYPTOPP_CPUID_AVAILABLE) && !defined(CRYPTOPP_BOOL_RDRAND_ASM)
# define CRYPTOPP_BOOL_RDRAND_ASM 1
#else
# define CRYPTOPP_BOOL_RDRAND_ASM 0
#endif
#if defined(CRYPTOPP_CPUID_AVAILABLE) && !defined(CRYPTOPP_BOOL_RDSEED_ASM)
# define CRYPTOPP_BOOL_RDSEED_ASM 1
#else
# define CRYPTOPP_BOOL_RDSEED_ASM 0
#endif

#if defined(CRYPTOPP_CPUID_AVAILABLE)
# define MSC_INTRIN_COMPILER ((CRYPTOPP_MSC_VERSION >= 1700) || (CRYPTOPP_CLANG_VERSION >= 30200) || (_INTEL_COMPILER >= 1210))
# define GCC_INTRIN_COMPILER ((CRYPTOPP_GCC_VERSION >= 40600) || (CRYPTOPP_CLANG_VERSION >= 30200) || (_INTEL_COMPILER >= 1210))
#else
# define MSC_INTRIN_COMPILER 0
# define GCC_INTRIN_COMPILER 0
#endif

// In general, the library's ASM code is best on Windows, and Intrinsics is
//   the best code under GCC and compatibles. We favor them accordingly.
//   The NASM code is optimized well on Linux, but its not easy to cut-in.
#if defined(CRYPTOPP_CPUID_AVAILABLE) && (CRYPTOPP_MSC_VERSION >= 1200)
#  if CRYPTOPP_BOOL_RDRAND_ASM
#    define MASM_RDRAND_ASM_AVAILABLE 1
#  elif MSC_INTRIN_COMPILER
#    define ALL_RDRAND_INTRIN_AVAILABLE 1
#  endif
#  if CRYPTOPP_BOOL_RDSEED_ASM
#    define MASM_RDSEED_ASM_AVAILABLE 1
#  elif MSC_INTRIN_COMPILER
#    define ALL_RDSEED_INTRIN_AVAILABLE 1
#  endif
#elif defined(CRYPTOPP_CPUID_AVAILABLE) && (CRYPTOPP_GCC_VERSION >= 30200)
#  if GCC_INTRIN_COMPILER && defined(__RDRND__)
#    define ALL_RDRAND_INTRIN_AVAILABLE 1
#  elif CRYPTOPP_BOOL_RDRAND_ASM
#    define GCC_RDRAND_ASM_AVAILABLE 1
#  endif
#  if GCC_INTRIN_COMPILER && defined(__RDSEED__)
#    define ALL_RDSEED_INTRIN_AVAILABLE 1
#  elif CRYPTOPP_BOOL_RDSEED_ASM
#    define GCC_RDSEED_ASM_AVAILABLE 1
#  endif
#endif

// Debug diagnostics
#if 0
#  if MASM_RDRAND_ASM_AVAILABLE
#    pragma message ("MASM_RDRAND_ASM_AVAILABLE is 1")
#  elif NASM_RDRAND_ASM_AVAILABLE
#    pragma message ("NASM_RDRAND_ASM_AVAILABLE is 1")
#  elif GCC_RDRAND_ASM_AVAILABLE
#    pragma message ("GCC_RDRAND_ASM_AVAILABLE is 1")
#  elif ALL_RDRAND_INTRIN_AVAILABLE
#    pragma message ("ALL_RDRAND_INTRIN_AVAILABLE is 1")
#  else
#    pragma message ("RDRAND is not available")
#  endif
#  if MASM_RDSEED_ASM_AVAILABLE
#    pragma message ("MASM_RDSEED_ASM_AVAILABLE is 1")
#  elif NASM_RDSEED_ASM_AVAILABLE
#    pragma message ("NASM_RDSEED_ASM_AVAILABLE is 1")
#  elif GCC_RDSEED_ASM_AVAILABLE
#    pragma message ("GCC_RDSEED_ASM_AVAILABLE is 1")
#  elif ALL_RDSEED_INTRIN_AVAILABLE
#    pragma message ("ALL_RDSEED_INTRIN_AVAILABLE is 1")
#  else
#    pragma message ("RDSEED is not available")
#  endif
#endif

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

#if (ALL_RDRAND_INTRIN_AVAILABLE || ALL_RDSEED_INTRIN_AVAILABLE)
# include <immintrin.h> // rdrand, MSC, ICC, and GCC
# if defined(__has_include)
#  if __has_include(<x86intrin.h>)
#   include <x86intrin.h> // rdseed for some compilers, like GCC
#  endif
# endif
#endif

#if MASM_RDRAND_ASM_AVAILABLE
# ifdef _M_X64
extern "C" int CRYPTOPP_FASTCALL MASM_RRA_GenerateBlock(byte*, size_t, unsigned int);
// #  pragma comment(lib, "rdrand-x64.lib")
# else
extern "C" int MASM_RRA_GenerateBlock(byte*, size_t, unsigned int);
// #  pragma comment(lib, "rdrand-x86.lib")
# endif
#endif

#if MASM_RDSEED_ASM_AVAILABLE
# ifdef _M_X64
extern "C" int CRYPTOPP_FASTCALL MASM_RSA_GenerateBlock(byte*, size_t, unsigned int);
// #  pragma comment(lib, "rdrand-x64.lib")
# else
extern "C" int MASM_RSA_GenerateBlock(byte*, size_t, unsigned int);
// #  pragma comment(lib, "rdrand-x86.lib")
# endif
#endif

#if NASM_RDRAND_ASM_AVAILABLE
extern "C" int NASM_RRA_GenerateBlock(byte*, size_t, unsigned int);
#endif

#if NASM_RDSEED_ASM_AVAILABLE
extern "C" int NASM_RSA_GenerateBlock(byte*, size_t, unsigned int);
#endif
	
/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

NAMESPACE_BEGIN(CryptoPP)
	
#if ALL_RDRAND_INTRIN_AVAILABLE
static int ALL_RRI_GenerateBlock(byte *output, size_t size, unsigned int safety)
{
	assert((output && size) || !(output || size));
#if CRYPTOPP_BOOL_X64 || CRYTPOPP_BOOL_X32
	word64 val;
#else
	word32 val;
#endif

	while (size >= sizeof(val))
	{
#if CRYPTOPP_BOOL_X64 || CRYTPOPP_BOOL_X32
		if (_rdrand64_step((word64*)output))
#else
		if (_rdrand32_step((word32*)output))
#endif
        {
			output += sizeof(val);
			size -= sizeof(val);
        }
        else
        {
			if (!safety--)
				return 0;
        }
	}

	if (size)
	{
#if CRYPTOPP_BOOL_X64 || CRYTPOPP_BOOL_X32
		if (_rdrand64_step(&val))
#else
		if (_rdrand32_step(&val))
#endif
		{
			memcpy(output, &val, size);
			size = 0;
		}
		else
		{
			if (!safety--)
				return 0;
		}
    }
		
#if CRYPTOPP_BOOL_X64 || CRYTPOPP_BOOL_X32
	*((volatile word64*)&val) = 0;
#else
	*((volatile word32*)&val) = 0;
#endif

	return int(size == 0);
}
#endif // ALL_RDRAND_INTRINSIC_AVAILABLE

#if GCC_RDRAND_ASM_AVAILABLE
static int GCC_RRA_GenerateBlock(byte *output, size_t size, unsigned int safety)
{
	assert((output && size) || !(output || size));
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	word64 val;
#else
	word32 val;
#endif
	char rc;
	while (size)
	{
        /*__asm__ volatile(
#if CRYPTOPP_BOOL_X64 
			".byte 0x48, 0x0f, 0xc7, 0xf0;\n"  // rdrand rax
#else
			".byte 0x0f, 0xc7, 0xf0;\n"        // rdrand eax
#endif
			"setc %1; "
			: "=a" (val), "=qm" (rc)
			:
			: "cc"
        );*/ /// comment by xueyu, compile error on my mac

		if (rc)
        {
			if (size >= sizeof(val))
			{
#if defined(CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS) && (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32)
				*((word64*)output) = val;
#elif defined(CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS) && (CRYPTOPP_BOOL_X86)
				*((word32*)output) = val;
#else
				memcpy(output, &val, sizeof(val));
#endif
				output += sizeof(val);
				size -= sizeof(val);
			}
			else
			{
				memcpy(output, &val, size);
				size = 0;
			}
        }
        else
        {
			if (!safety--)
				break;
        }
	}

#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	*((volatile word64*)&val) = 0;
#else
	*((volatile word32*)&val) = 0;
#endif

	return int(size == 0);
}

#endif // GCC_RDRAND_ASM_AVAILABLE

#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
void RDRAND::GenerateBlock(byte *output, size_t size)
{
	CRYPTOPP_UNUSED(output), CRYPTOPP_UNUSED(size);
	assert((output && size) || !(output || size));

	if(!HasRDRAND())
		throw NotImplemented("RDRAND: rdrand is not available on this platform");

	int rc; CRYPTOPP_UNUSED(rc);
#if MASM_RDRAND_ASM_AVAILABLE
	rc = MASM_RRA_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDRAND_Err("MASM_RRA_GenerateBlock"); }
#elif NASM_RDRAND_ASM_AVAILABLE
	rc = NASM_RRA_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDRAND_Err("NASM_RRA_GenerateBlock"); }
#elif ALL_RDRAND_INTRIN_AVAILABLE
	rc = ALL_RRI_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDRAND_Err("ALL_RRI_GenerateBlock"); }
#elif GCC_RDRAND_ASM_AVAILABLE
	rc = GCC_RRA_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDRAND_Err("GCC_RRA_GenerateBlock"); }
#else
	// RDRAND not detected at compile time, and no suitable compiler found
	throw NotImplemented("RDRAND: failed to find a suitable implementation???");
#endif // CRYPTOPP_CPUID_AVAILABLE
}

void RDRAND::DiscardBytes(size_t n)
{
	// RoundUpToMultipleOf is used because a full word is read, and its cheaper
	//   to discard full words. There's no sense in dealing with tail bytes.
	assert(HasRDRAND());
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	FixedSizeSecBlock<word64, 16> discard;
	n = RoundUpToMultipleOf(n, sizeof(word64));
#else
	FixedSizeSecBlock<word32, 16> discard;
	n = RoundUpToMultipleOf(n, sizeof(word32));
#endif

	size_t count = STDMIN(n, discard.SizeInBytes());
	while (count)
	{
		GenerateBlock(discard.BytePtr(), count);
		n -= count;
		count = STDMIN(n, discard.SizeInBytes());
	}
}
#endif // CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

#if ALL_RDSEED_INTRIN_AVAILABLE
static int ALL_RSI_GenerateBlock(byte *output, size_t size, unsigned int safety)
{
	assert((output && size) || !(output || size));
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	word64 val;
#else
	word32 val;
#endif

	while (size >= sizeof(val))
	{
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
		if (_rdseed64_step((word64*)output))
#else
		if (_rdseed32_step((word32*)output))
#endif
        {
			output += sizeof(val);
			size -= sizeof(val);
        }
        else
        {
			if (!safety--)
				return 0;
        }
	}

	if (size)
	{
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
		if (_rdseed64_step(&val))
#else
		if (_rdseed32_step(&val))
#endif
		{
			memcpy(output, &val, size);
			size = 0;
		}
		else
		{
			if (!safety--)
				return 0;
		}
    }
		
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	*((volatile word64*)&val) = 0;
#else
	*((volatile word32*)&val) = 0;
#endif

	return int(size == 0);
}
#endif // ALL_RDSEED_INTRIN_AVAILABLE

#if GCC_RDSEED_ASM_AVAILABLE
static int GCC_RSA_GenerateBlock(byte *output, size_t size, unsigned int safety)
{
	assert((output && size) || !(output || size));
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	word64 val;
#else
	word32 val;
#endif
	char rc;
	while (size)
	{
        /*__asm__ volatile(
#if CRYPTOPP_BOOL_X64 
			".byte 0x48, 0x0f, 0xc7, 0xf8;\n"  // rdseed rax
#else
			".byte 0x0f, 0xc7, 0xf8;\n"        // rdseed eax
#endif
			"setc %1; "
			: "=a" (val), "=qm" (rc)
			:
			: "cc"
        );*/ /// comment by xueyu, compile error on my mac

		if (rc)
        {
			if (size >= sizeof(val))
			{
#if defined(CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS) && (CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32)
				*((word64*)output) = val;
#elif defined(CRYPTOPP_ALLOW_UNALIGNED_DATA_ACCESS) && (CRYPTOPP_BOOL_X86)
				*((word32*)output) = val;
#else
				memcpy(output, &val, sizeof(val));
#endif
				output += sizeof(val);
				size -= sizeof(val);
			}
			else
			{
				memcpy(output, &val, size);
				size = 0;
			}
        }
        else
        {
			if (!safety--)
				break;
        }
	}

#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	*((volatile word64*)&val) = 0;
#else
	*((volatile word32*)&val) = 0;
#endif

	return int(size == 0);
}
#endif // GCC_RDSEED_ASM_AVAILABLE

#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
void RDSEED::GenerateBlock(byte *output, size_t size)
{
	CRYPTOPP_UNUSED(output), CRYPTOPP_UNUSED(size);
	assert((output && size) || !(output || size));

	if(!HasRDSEED())
		throw NotImplemented("RDSEED: rdseed is not available on this platform");

	int rc; CRYPTOPP_UNUSED(rc);
#if MASM_RDSEED_ASM_AVAILABLE
	rc = MASM_RSA_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDSEED_Err("MASM_RSA_GenerateBlock"); }
#elif NASM_RDSEED_ASM_AVAILABLE
	rc = NASM_RSA_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDRAND_Err("NASM_RSA_GenerateBlock"); }
#elif ALL_RDSEED_INTRIN_AVAILABLE
	rc = ALL_RSI_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDSEED_Err("ALL_RSI_GenerateBlock"); }
#elif GCC_RDSEED_ASM_AVAILABLE
	rc = GCC_RSA_GenerateBlock(output, size, m_retries);
	if (!rc) { throw RDSEED_Err("GCC_RSA_GenerateBlock"); }
#else
	// RDSEED not detected at compile time, and no suitable compiler found
	throw NotImplemented("RDSEED: failed to find a suitable implementation???");
#endif
}

void RDSEED::DiscardBytes(size_t n)
{
	// RoundUpToMultipleOf is used because a full word is read, and its cheaper
	//   to discard full words. There's no sense in dealing with tail bytes.
	assert(HasRDSEED());
#if CRYPTOPP_BOOL_X64 || CRYPTOPP_BOOL_X32
	FixedSizeSecBlock<word64, 16> discard;
	n = RoundUpToMultipleOf(n, sizeof(word64));
#else
	FixedSizeSecBlock<word32, 16> discard;
	n = RoundUpToMultipleOf(n, sizeof(word32));
#endif

	size_t count = STDMIN(n, discard.SizeInBytes());
	while (count)
	{
		GenerateBlock(discard.BytePtr(), count);
		n -= count;
		count = STDMIN(n, discard.SizeInBytes());
	}
}
#endif // CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64

NAMESPACE_END
