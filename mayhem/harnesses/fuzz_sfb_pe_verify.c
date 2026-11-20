// libFuzzer harness for the super-fastboot secure-boot gate SfbSecurityVerifyImage()
// (submodules/uefi/edk2/QcomModulePkg/Library/SfbSecurityLib/SfbPeVerify.c): PE/PE32+ header
// parse, authentihash, WIN_CERTIFICATE table walk, PKCS#7 parse + signature check (mbedtls, the
// copy vendored in CryptoPkg/Library/MbedTlsLib/mbedtls). The input is an EFI image the BDS is
// asked to launch. The BOOT_CERTS pool (SfbCerts.c, loaded from the trusted config store) is
// provided by sfb_cert_pool.c with one fixed certificate, since with an empty pool the
// verifier accepts every image without parsing it.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <Uefi.h>
#include <Library/SfbSecurity.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Exact-size heap copy so ASan sees reads past the image.
    uint8_t *img = (uint8_t *)malloc(size ? size : 1);
    if (!img) return 0;
    if (size) memcpy(img, data, size);
    (void)SfbSecurityVerifyImage(img, size);
    free(img);
    return 0;
}
