#include <stdio.h>
#include <string.h> 
#include <capstone/capstone.h>

#define COLOR "\x1b[32m"
#define RESET "\x1b[0m"

void 
converter (const unsigned char* shellcode, size_t length) 
{
  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) 
    {
      printf("[!] Capstone error\n");
      return;
    }

  count = cs_disasm(handle, shellcode, length, 0x1000, 0, &insn);
  if (count > 0) 
    {
      size_t j;
      for (j = 0; j < count; j++) printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);

      cs_free(insn, count);
    } 
  else 
    {
      printf("[!] Disassembly error\n");
    }

  cs_close(&handle);
}

int
main (int argc, char** argv)
{
  if (argc != 2) 
    {
      printf("Use: %s <shellcode>\n", argv[0]);
      return 1;
    }

  unsigned char shellcode[256];
  size_t length = 0;

  const char *input = argv[1];
  while (*input && length < sizeof(shellcode)) 
    {
      if (*input == '\\' && *(input+1) == 'x') 
        {
          sscanf(input + 2, "%2hhx", &shellcode[length]);
          length++;
          input += 4;
        } 
      else 
        {
          input++;
        }
    }

  printf(COLOR "\n[+]" RESET " Shellcode: ");
  for (size_t i = 0; i < length; i++) printf("\\x%02x", shellcode[i]);
  printf("\n\n");

  printf(COLOR "[+]" RESET " Converted:\n\n");
  converter(shellcode, length);
  printf("\n");

  return 0;
}
