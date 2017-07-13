#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void usage(char *name) {
  fprintf(stderr, "usage(): %s <hexa_error_code>\n", name);
  exit(1);
}

union txt_error_code {
  uint32_t raw;
  struct {
    union {
      struct {
        uint16_t type2:15;
        uint16_t _r0:1;
      };
      struct {
        uint16_t module_type:4;
        uint16_t class_code:6;
        uint16_t major_error_code:5;
        uint16_t sw_source:1;
      };
    };
    union {
      struct {
        uint16_t type1:14;
        uint16_t external:1;
        uint16_t valid:1;
      };
      struct {
        uint16_t extended_value:8;
        uint16_t _r1:6;
        uint16_t _p0:2;
      };
      struct {
        uint16_t minor_error_code:12;
        uint16_t _r2:2;
        uint16_t _p1:2;
      };
    };
  };
};

enum txt_class_codes {
  CLASS_CODE_ACM_ENTRY_BIOS_AC_AND_SINIT = 0x1,
  CLASS_CODE_MTRR_CHECK_BIOS_AC_AND_SINIT = 0x2,
  CLASS_CODE_TPM_ACCESS_BIOS_AC_AND_SINIT = 0x4,
  CLASS_CODE_LAUNCH_CONTROL_POLICY_BIOS_AC_AND_SINIT = 0x6,
  CLASS_CODE_HEAP_TABLE_DATA_SINIT = 0x9,
  CLASS_CODE_PMR_CONFIGURATION_SINIT = 0xe,
  CLASS_CODE_MLE_HEADER_CHECK_SINIT = 0xf,
  CLASS_CODE_MLE_PAGE_TABLES_CHECK_SINIT = 0x10,
  CLASS_CODE_EVENT_LOG_SINIT = 0x14,
};

#define CASE_PRINT(x) case CLASS_CODE_ ## x: fprintf(out, "    " #x "\n");

void decode(FILE *out, union txt_error_code *tec) {
  fprintf(out, "Generic register values\n");
  fprintf(out, "  valid(%d)\n  external(%d)\n  type1(0x%02hx)\n  sw_source(%d)"
      "\n  type2(%02hx)\n", tec->valid, tec->external, tec->type1,
      tec->sw_source, tec->type2);
  if (tec->external) {
    fprintf(out, "ACM-initiated TXT-shutdown\n");
    fprintf(out, "  module_type(");
    if (tec->module_type) {
      fprintf(out, "SINIT");
    } else {
      fprintf(out, "BIOS ACM");
    }
    fprintf(out, ")\n");
    fprintf(out, "  class_code(0x%02hhx)\n", tec->class_code);
    fprintf(out, "  major_error_code(0x%02hhx)\n", tec->major_error_code);
    fprintf(out, "  minor_error_code(0x%02hhx)\n", tec->minor_error_code);
    switch (tec->class_code) {
      CASE_PRINT(ACM_ENTRY_BIOS_AC_AND_SINIT)
        switch (tec->major_error_code) {
          case 1:
            fprintf(out, "      error in ACM launching\n");
            break;
          case 3:
            fprintf(out, "      client SINIT detected LTSX fused processor or"
                "Server SINIT detected non- LTSX fused processor\n");
            break;
          case 9:
            fprintf(out, "      ACM is revoked\n");
            break;
          default:
            fprintf(out, "      bad major error code\n");
        }
        break;
      CASE_PRINT(MTRR_CHECK_BIOS_AC_AND_SINIT)
        switch (tec->major_error_code) {
          case 1:
            fprintf(out, "      MTRR Rule 1 Error\n");
            break;
          case 2:
            fprintf(out, "      MTRR Rule 2 Error\n");
            break;
          case 3:
            fprintf(out, "      MTRR Rule 3 Error\n");
            break;
          case 4:
            fprintf(out, "      MTRR Rule 4 Error\n");
            break;
          case 5:
            fprintf(out, "      MTRR Rule 5 Error\n");
            break;
          case 6:
            fprintf(out, "      MTRR Rule 6 Error\n");
            break;
          case 7:
            fprintf(out, "      invalid MTRR mask value\n");
          default:
            fprintf(out, "      bad major error code\n");
        }
        break;
      CASE_PRINT(TPM_ACCESS_BIOS_AC_AND_SINIT)
        switch (tec->major_error_code) {
          case 1:
            fprintf(out, "      TPM returned an error\n");
            break;
          case 5:
            fprintf(out, "      TPM 1.2 disabled\n");
            break;
          case 6:
            fprintf(out, "      TPM 1.2 deactivated\n");
            break;
          case 0xd:
            fprintf(out, "      TPM 2.0 interface type (FIFO/CRB) not "
                "supported\n");
            break;
          case 0xe:
            fprintf(out, "      TPM family (1.2/2.0) not supported\n");
            break;
          case 0xf:
            fprintf(out, "      Discovered number of TPM 2.0 PCR banks exceeds"
                "supported maximum (3)\n");
            break;
          case 0x10:
            fprintf(out, "      Required TPM hash algorithm not supported\n");
            break;
          default:
            fprintf(out, "      bad major error code\n");
        }
        break;
      CASE_PRINT(LAUNCH_CONTROL_POLICY_BIOS_AC_AND_SINIT)
        switch (tec->major_error_code) {
          case 2:
            fprintf(out, "      SINIT version is below minimum specified in TPM"
                " NV policy index\n");
            break;
          case 4:
            fprintf(out, "      No match is found for Policy Element\n");
            break;
          case 5:
            fprintf(out, "      Auto-promotion failed. BIOS hash differs from "
                "hash value saved in AUX index\n");
            break;
          case 6:
            fprintf(out, "      Failsafe boot failed. (FIT table not found or "
                "corrupted)\n");
            break;
          case 7:
            fprintf(out, "      PO integrity check failed\n");
            break;
          case 8:
            fprintf(out, "      PS integrity check failed\n");
            break;
          case 9:
            fprintf(out, "      No policies are defined to allow NPW "
                "execution\n");
            break;
          case 0xa:
            fprintf(out, "      PS TPM NV policy index is required but"
                "not defined\n");
            break;
          default:
            fprintf(out, "      bad major error code\n");
        }
        break;
      CASE_PRINT(HEAP_TABLE_DATA_SINIT)
        switch (tec->major_error_code) {
          case 1:
            fprintf(out, "      Invalid size of one of the heap data tables\n");
            break;
          case 2:
            fprintf(out, "      Invalid version of one of the heap data"
                "tables\n");
            break;
          case 3:
            fprintf(out, "      Invalid PMR Low range alignment\n");
            break;
          case 4:
            fprintf(out, "      Invalid PMR High range alignment\n");
            break;
          case 5:
            fprintf(out, "      Invalid MLE placement (Above 4GB)\n");
            break;
          case 6:
            fprintf(out, "      Invalid MLE requested capabilities\n");
            break;
          case 7:
            fprintf(out, "      Heap region is overfilled\n");
            break;
          case 8:
            fprintf(out, "      Unsupported heap extended element type\n");
            break;
          case 9:
            fprintf(out, "      Invalid heap extended element size\n");
            break;
          case 0xa:
            fprintf(out, "      Heap table is not terminated by the extended "
                "\"END\" element\n");
            break;
          case 0xb:
            fprintf(out, "      Invalid event log pointer\n");
            break;
          case 0xc:
            fprintf(out, "      Invalid RSDT/RSDP pointer in OsSinitData"
                "table\n");
            break;
          default:
            fprintf(out, "      bad major error code\n");
        }
        break;
      CASE_PRINT(PMR_CONFIGURATION_SINIT)
        switch (tec->major_error_code) {
          case 1:
            fprintf(out, "      DMA remapping is enabled\n");
            break;
          case 2:
            fprintf(out, "      Invalid PMR Low configuration\n");
            break;
          case 3:
            fprintf(out, "      Invalid PMR High configuration\n");
            break;
          default:
            fprintf(out, "      bad major error code\n");
        }
        break;
      CASE_PRINT(MLE_HEADER_CHECK_SINIT)
        switch (tec->major_error_code) {
          case 1:
            fprintf(out, "      MLE Header linear address conversion error\n");
            break;
          case 2:
            fprintf(out, "      Invalid MLE GUID\n");
            break;
          case 3:
            fprintf(out, "      Invalid MLE version\n");
            break;
          case 4:
            fprintf(out, "      Invalid first page address\n");
            break;
          case 5:
            fprintf(out, "      Invalid MLE size\n");
            break;
          case 6:
            fprintf(out, "      Invalid MLE entry point address\n");
            break;
          case 7:
            fprintf(out, "      Incompatible RLM wake-up method\n");
            break;
          default:
            fprintf(out, "      bad major error code\n");
        }
        break;
      CASE_PRINT(MLE_PAGE_TABLES_CHECK_SINIT)
        switch (tec->major_error_code) {
          case 1:
            fprintf(out, "      Page placement error\n");
            break;
          case 2:
            fprintf(out, "      MLE page order rule failure - next page is not "
                "above previous one\n");
            break;
          case 3:
            fprintf(out, "      Discovered big page (2MB)\n");
            break;
          case 4:
            fprintf(out, "      Page Table order rule failure - PDPT, PDT, PT, "
               " MLE pages are not in ascending order\n");
            break;
          case 5:
            fprintf(out, "      Invalid MLE hashed size\n");
            break;
          case 6:
            fprintf(out, "      Invalid RLP entry point address\n");
            break;
          default:
            fprintf(out, "      bad major error code\n");
        }
        break;
      CASE_PRINT(EVENT_LOG_SINIT)
        switch (tec->major_error_code) {
          case 1:
            fprintf(out, "      Invalid Log Header GUID\n");
            break;
          case 2:
            fprintf(out, "      Invalid Log Header version\n");
            break;
          case 3:
            fprintf(out, "      Inconsistent values of header fields\n");
            break;
          case 4:
            fprintf(out, "      Insufficient log size\n");
            break;
          case 5:
            fprintf(out, "      Unsupported record version\n");
            break;
          default:
            fprintf(out, "      bad major error code\n");
        }

        break;
      default:
        fprintf(out, "    bad class code\n");
    }
  } else {
    fprintf(out, "CPU-initiated TXT-shutdown\n");
  }
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage(argv[0]);
  }
  union txt_error_code tec = {.raw = strtol(argv[1], NULL, 16)};
  printf("Error code : 0x%08x\n", tec.raw);
  decode(stdout, &tec);
  return 0;
}
