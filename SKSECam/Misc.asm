;                             The MIT License (MIT)
;
;            Copyright (c) 2016 Sumwunn @ github.com
;
;Permission is hereby granted, free of charge, to any person obtaining a copy of
; this software and associated documentation files (the "Software"), to deal in
;  the Software without restriction, including without limitation the rights to
;use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
;the Software, and to permit persons to whom the Software is furnished to do so,
;                      subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
;                copies or substantial portions of the Software.
;
;   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
;IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
; FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
; COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
;    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
;   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

IFDEF _WIN32

.486
.MODEL FLAT, C
OPTION CASEMAP:NONE

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

.code

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

ENDIF

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

IFDEF _WIN64

.x64
OPTION CASEMAP:NONE
OPTION FRAME:AUTO
OPTION WIN64:11
OPTION STACKBASE:RSP

.code

BinSearchX proc frame

jmp BinSearch

BinSearchX endp


; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

BinSearch proc frame uses rsi rdi SearchAddress:QWORD, SearchLength:DWORD, BytesAddress:QWORD, BytesLength:DWORD, AddMod:DWORD, SubMod:DWORD

; Setup Search.
mov rcx, [SearchAddress]
xor rdx, rdx
; Get end of Search.
mov edx, [SearchLength]
add rdx, rcx
; Setup Bytes.
mov r8, [BytesAddress]
xor r9, r9
; Get the end of Bytes.
mov r9d, [BytesLength]
add r9, r8
; Setup the first bytes.
mov sil, byte ptr [rcx]
mov dil, byte ptr [r8]
; Reset bytes found counter.
xor eax, eax

Begin:
; Find first byte.
.while sil != dil
; Prevent overrread of Search & Bytes.
cmp rcx, rdx
jnle NothingFound
cmp r8, r9
jnle NothingFound
; Next byte.
inc rcx
; Load next byte.
mov sil, byte ptr [rcx]
.endw
; Increment bytes found counter.
inc eax
; Next bytes.
inc rcx
inc r8
; Load next bytes.
mov sil, byte ptr [rcx]
mov dil, byte ptr [r8]

; First byte found, find the rest of the bytes.
.while sil == dil
; Prevent overrread of Search & Bytes.
cmp rcx, rdx
jnle NothingFound
cmp r8, r9
jnle NothingFound
; Next bytes.
inc eax
inc rcx
inc r8
; Load next bytes.
mov sil, byte ptr [rcx]
mov dil, byte ptr [r8]
; If all bytes found, return address of which the first byte was found.
.if eax == [BytesLength]
; Rewind address.
sub rcx, rax
; Apply modifiers.
mov eax, [AddMod]
add rcx, rax
mov eax, [SubMod]
sub rcx, rax
; Return address.
mov rax, rcx
ret
.endif
.endw

; Bytes not found, reset Bytes & jump back to StepOne.
sub r8, rax ; Rewind Bytes.
xor eax, eax
inc rcx
; Load next bytes.
mov sil, byte ptr [rcx]
mov dil, byte ptr [r8]
jmp Begin

NothingFound:
xor rax, rax
ret

BinSearch endp

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

GetTextSectionAddr proc frame

jmp GetTextSectionData

GetTextSectionAddr endp

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

GetTextSectionSize proc frame

jmp GetTextSectionData

GetTextSectionSize endp

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

GetTextSectionData proc frame Module:QWORD, DataType:DWORD

; 1 = Section VirtualSize
; 2 = Section VirtualAddress

; Get imagebase.
mov rcx, [Module]
xor rax, rax
; Get PE header.
mov eax, [rcx+3Ch]
add rcx, rax

.if [DataType] == 1
; Get .text section VirtualSize.
mov eax, [rcx+110h]
ret
.elseif [DataType] == 2
; Get .text section VirtualAddress.
mov eax, [rcx+114h]
; Make it an actual VirtualAddress.
add rax, [Module]
ret
.endif

xor rax, rax
ret

GetTextSectionData endp

; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

ENDIF


; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
; Patch SkyrimSE code to apply French possesive form in containers name
; Hircine 's Cercueil > Cercueil d'Hircine


Container_ApplyHook proc frame BAdress:QWORD

;$ ==>            | F6 C1 01                 | test cl,1                               |BAdress
;$+3              | 74 37                    | je skyrimse.7FF61125BC44                |
;$+5              | 4D 85 FF                 | test r15,r15                            |
;$+8              | 74 32                    | je skyrimse.7FF61125BC44                |
;$+A              | 49 8B CF                 | mov rcx,r15                             |
;$+D              | E8 76 B3 F6 FF           | call <skyrimse.GetOwner>                |CallGO
;$+12             | 4C 8B C0                 | mov r8,rax                              | 
;$+15             | 48 8D 4C 24 30           | lea rcx,qword ptr ss:[rsp+30]           |
;$+1A             | BA 04 01 00 00           | mov edx,104                             |
;$+1F             | FF 15 E3 73 2F 01        | call qword ptr ds:[<&strcpy_s>]         |
;$+25             | 4C 8D 05 50 72 34 01     | lea r8,qword ptr ds:[7FF6125A2E84]      | 0x00007FF6125A2E84:"'s "
;$+2C             | BA 04 01 00 00           | mov edx,104                             |
;$+31             | 48 8D 4C 24 30           | lea rcx,qword ptr ss:[rsp+30]           |
;$+36             | FF 15 1C 73 2F 01        | call qword ptr ds:[<&strcat_s>]         |
;$+3C             | 48 8B CB                 | mov rcx,rbx                             | 
;$+3F             | E8 24 A7 06 00           | call <skyrimse.GetName>                 |CallGN
;$+44             | 4C 8B C0                 | mov r8,rax                              | 
;$+47             | 48 8D 4C 24 30           | lea rcx,qword ptr ss:[rsp+30]           |
;$+4C             | BA 04 01 00 00           | mov edx,104                             |
;$+51             | FF 15 01 73 2F 01        | call qword ptr ds:[<&strcat_s>]         |

;GetOwner-CallGO-5 = FFFFFFFF F6B376
;CallGO+5+FFF6B376 = Absolute adress of GetOwner

;First we need to get the GetOwner Address (= the procedure used to get the container owner string)
mov rcx, [BAdress] ; put base address in rax
add rcx, 0xD ; points to E8 (call GetOwner)
push rcx
pop tmpaddr 
call CalculateAddress
push rax
pop GetOwnerAddr


;THen we need to get the GetName Address (= the procedure used to get the container name string)
mov rcx, [BAdress] ; put base address in rax
add rcx, 0x3F ; points to E8 (call GetOwner)
push rcx
pop tmpaddr 
call CalculateAddress
push rax
pop GetNameAddr


;THen we need to get the address of strcpy_s 
mov rcx, [BAdress] ; put base address in rax
add rcx, 0x1F ; points to E8 (call strcpy_s)
push rcx
pop tmpaddr 
call CalculateAddress
mov rax, [rax]
push rax
pop strcpy_s

;THen we need to get the address of strcat_s 
mov rcx, [BAdress] ; put base address in rax
add rcx, 0x36 ; points to E8 (call strcat_s)
push rcx
pop tmpaddr 
call CalculateAddress
mov rax, [rax]
push rax
pop strcat_s

;landing Address (where to jump back after manipulation)
mov rax, [BAdress]
add rax, 0x57
push rax
pop Container_LandingAddr


;Patch BAdress+A to 
; MOV RAX, HookContainerFunction
; JMP RAX

mov rax, [BAdress]
add rax, 0xA
mov word ptr [rax], 0xB848; Section access should be PAGE_READWRITEXECUTE at this point otherwise we are fucked up
mov rcx, HookContainerFunction
mov qword ptr [rax+2], rcx
mov word ptr [rax+0xA], 0xE0FF ; JMP RAX

ret

Container_ApplyHook endp


; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

;Calculate the absolute adresse of a call (E8 XX XX XX XX, or FF 15 XX XX XX XX) at MemoryAdress
CalculateAddress proc frame 

mov rax,  [tmpaddr]
xor rbx, rbx
xor ecx, ecx
inc ecx

cmp word ptr [rax], 0x15FF
jne notindirectcall

inc rcx

notindirectcall:

mov ebx, dword ptr [rax+rcx]

test ebx, 0x80000000
jns DOADD

;Signed
neg ebx
sub rax, rbx
jmp ADD5


;Unsigned
DOADD:
add rax, rbx

ADD5:
add rax, 4 ; We need to add 5 for a direct (E8) call, and 6 for an indirect call (FF15). Hence, we can ALWAYS add 4, and THEN add rcx which is 1 or 2 .
add rax, rcx

mov [tmpaddr], rax


ret
CalculateAddress endp


; ¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

;The function that computes the Container new string :D

HookContainerFunction:


; GetName
mov rcx, rbx
call [GetNameAddr]

;copy into buffer
;Call strcpy_s sample (same for strcat_s)
;00007FF61125BC1A | 4C 8B C0                                   | mov r8,rax                              |   R8  > string to concat
;00007FF61125BC1D | 48 8D 4C 24 30                             | lea rcx,qword ptr ss:[rsp+30]           | > RCX > Buffer
;00007FF61125BC22 | BA 04 01 00 00                             | mov edx,104                             | > edx > max lentgh
;00007FF61125BC27 | FF 15 E3 73 2F 01                          | call qword ptr ds:[<&strcpy_s>]         | > call

mov r8, rax
lea rcx,qword ptr [rsp+0x30] 
mov edx, 0x104
call [strcpy_s]


;Get the good form to use : d'or de
;0106A959                                                    57                    PUSH    EDI
;0106A95A                                                    E8 A1793EFF           CALL    <GetOwner>
;0106A95F                                                    83C4 04               ADD     ESP, 4
;0106A962                                                    0FBE18                MOVSX   EBX, BYTE PTR DS:[EAX]
;0106A965                                                    80CB 20               OR      BL, 20
;0106A968                                                    80FB 68               CMP     BL, 68                                                                      ;  cmp, bl, "h"
;0106A96B                                                    75 03                 JNZ     SHORT 0106A970
;0106A96D                                                    40                    INC     EAX
;0106A96E                                                  ^ EB F2                 JMP     SHORT 0106A962
;0106A970                                                    80FB 61               CMP     BL, 61
;0106A973                                                    74 23                 JE      SHORT 0106A998
;0106A975                                                    80FB 65               CMP     BL, 65
;0106A978                                                    74 1E                 JE      SHORT 0106A998
;0106A97A                                                    80FB 69               CMP     BL, 69
;0106A97D                                                    74 19                 JE      SHORT 0106A998
;0106A97F                                                    80FB 6F               CMP     BL, 6F
;0106A982                                                    74 14                 JE      SHORT 0106A998
;0106A984                                                    80FB 75               CMP     BL, 75
;0106A987                                                    74 0F                 JE      SHORT 0106A998
;0106A989                                                    80FB 79               CMP     BL, 79
;0106A98C                                                    74 0A                 JE      SHORT 0106A998
;0106A98E                                                    C74424 1C 4BA90601    MOV     DWORD PTR SS:[ESP+1C], <de>                                                 ;  ASCII " de "
;0106A996                                                    61                    POPAD
;0106A997                                                    C3                    RET
;0106A998                                                    C74424 1C 50A90601    MOV     DWORD PTR SS:[ESP+1C], <d'>                                                 ;  ASCII " d'"
;0106A9A0                                                    61                    POPAD
;0106A9A1                                                    C3                    RET

mov rcx, r15
call [GetOwnerAddr]

Suffixloop:

movsx rbx, BYTE PTR [rax] 
or bl, 0x20 ; lowercase
cmp bl, 00 ; if there is no more letters, put "de" by default
je _szde
cmp bl, 0x68
jnz testvoyels
inc rax
jmp Suffixloop

testvoyels:
CMP     BL, 0x61           ;a
JE      _szD
CMP     BL, 0x65           ;e
JE      _szD
CMP     BL, 0x69           ;i
JE      _szD
CMP     BL, 0x6F           ;o
JE      _szD
CMP     BL, 0x75           ;u
JE      _szD
CMP     BL, 0x79           ;y
JE      _szD

_szde:
mov rax, offset szDe
jmp concatDE

_szD:
mov rax, offset szD

concatDE:
mov r8, rax
lea rcx,qword ptr [rsp+0x30] 
mov edx, 0x104
call [strcat_s]


_getowner:
; GetOwner
mov rcx, r15
call [GetOwnerAddr]
mov r8, rax 
lea rcx,qword ptr [rsp+0x30] 
mov edx, 0x104
call [strcat_s]


;return to the main program code
jmp [Container_LandingAddr]

nop
nop
nop
nop
nop


.data?


GetNameAddr DQ ? 
GetOwnerAddr DQ ? 
Container_LandingAddr DQ ? 

strcpy_s DQ ? 
strcat_s DQ ? 

tmpaddr DQ ? 



.data

szDe db " de ",0
szD  db " d'",0


END


