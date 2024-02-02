.486
.387
option dotname
.model flat, c
assume fs:nothing

public FUN_100bd530
public FUN_100bd580
public FUN_100bd600
public FUN_100bd680
public FUN_100bd6e0
public FUN_100bd760
public FUN_100bd880
public FUN_100bd8a0
public FUN_100bd8f0
public FUN_100bd940
public FUN_100bd960
public FUN_100bda10
public FUN_100bdac0
public FUN_100bdc00
public FUN_100bdc90
public DecodeFLCFrame

; This is so reccmp can detect the end of DecodeFLCFrame
public EndOfSection

.text SEGMENT BYTE PUBLIC 'CODE'

FUN_100bd530 LABEL NEAR
        mov     ax, word ptr [esp+0CH]                  ; 100BD530 _ 66: 8B. 44 24, 0C
        push    esi                                     ; 100BD535 _ 56
        test    ax, ax                                  ; 100BD536 _ 66: 85. C0
        push    edi                                     ; 100BD539 _ 57
        jl      ?_25163                                 ; 100BD53A _ 7C, 34
        mov     cx, word ptr [esp+18H]                  ; 100BD53C _ 66: 8B. 4C 24, 18
        test    cx, cx                                  ; 100BD541 _ 66: 85. C9
        jl      ?_25163                                 ; 100BD544 _ 7C, 2A
        mov     edx, dword ptr [esp+0CH]                ; 100BD546 _ 8B. 54 24, 0C
        movsx   edi, ax                                 ; 100BD54A _ 0F BF. F8
        mov     esi, dword ptr [edx+4H]                 ; 100BD54D _ 8B. 72, 04
        cmp     esi, edi                                ; 100BD550 _ 3B. F7
        jle     ?_25163                                 ; 100BD552 _ 7E, 1C
        movsx   eax, cx                                 ; 100BD554 _ 0F BF. C1
        cmp     dword ptr [edx+8H], eax                 ; 100BD557 _ 39. 42, 08
        jle     ?_25163                                 ; 100BD55A _ 7E, 14
        add     esi, 3                                  ; 100BD55C _ 83. C6, 03
        mov     cl, byte ptr [esp+1CH]                  ; 100BD55F _ 8A. 4C 24, 1C
        and     esi, 0FFFFFFFCH                         ; 100BD563 _ 83. E6, FC
        imul    esi, eax                                ; 100BD566 _ 0F AF. F0
        add     esi, dword ptr [esp+10H]                ; 100BD569 _ 03. 74 24, 10
        mov     byte ptr [esi+edi], cl                  ; 100BD56D _ 88. 0C 3E
?_25163:pop     edi                                     ; 100BD570 _ 5F
        pop     esi                                     ; 100BD571 _ 5E
        ret                                             ; 100BD572 _ C3

; Filling space: 0DH
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH

FUN_100bd580 LABEL NEAR
        lea     eax, [esp+18H]                          ; 100BD580 _ 8D. 44 24, 18
        push    esi                                     ; 100BD584 _ 56
        mov     si, word ptr [esp+10H]                  ; 100BD585 _ 66: 8B. 74 24, 10
        push    edi                                     ; 100BD58A _ 57
        lea     ecx, [esp+18H]                          ; 100BD58B _ 8D. 4C 24, 18
        push    eax                                     ; 100BD58F _ 50
        lea     edx, [esp+18H]                          ; 100BD590 _ 8D. 54 24, 18
        push    ecx                                     ; 100BD594 _ 51
        mov     edi, dword ptr [esp+14H]                ; 100BD595 _ 8B. 7C 24, 14
        push    edx                                     ; 100BD599 _ 52
        push    edi                                     ; 100BD59A _ 57
        call    FUN_100bd600                            ; 100BD59B _ E8, 00000060
        add     esp, 16                                 ; 100BD5A0 _ 83. C4, 10
        test    eax, eax                                ; 100BD5A3 _ 85. C0
        jz      ?_25167                                 ; 100BD5A5 _ 74, 4A
        mov     ax, word ptr [esp+14H]                  ; 100BD5A7 _ 66: 8B. 44 24, 14
        sub     ax, si                                  ; 100BD5AC _ 66: 2B. C6
        jz      ?_25165                                 ; 100BD5AF _ 74, 0B
        movsx   eax, ax                                 ; 100BD5B1 _ 0F BF. C0
        mov     esi, dword ptr [esp+1CH]                ; 100BD5B4 _ 8B. 74 24, 1C
        add     esi, eax                                ; 100BD5B8 _ 03. F0
        jmp     ?_25166                                 ; 100BD5BA _ EB, 04

?_25165:mov     esi, dword ptr [esp+1CH]                ; 100BD5BC _ 8B. 74 24, 1C
?_25166:movsx   edx, word ptr [esp+20H]                 ; 100BD5C0 _ 0F BF. 54 24, 20
        mov     ecx, dword ptr [edi+4H]                 ; 100BD5C5 _ 8B. 4F, 04
        movsx   eax, word ptr [esp+18H]                 ; 100BD5C8 _ 0F BF. 44 24, 18
        add     ecx, 3                                  ; 100BD5CD _ 83. C1, 03
        and     ecx, 0FFFFFFFCH                         ; 100BD5D0 _ 83. E1, FC
        movsx   edi, word ptr [esp+14H]                 ; 100BD5D3 _ 0F BF. 7C 24, 14
        imul    ecx, eax                                ; 100BD5D8 _ 0F AF. C8
        add     ecx, edi                                ; 100BD5DB _ 03. CF
        mov     edi, dword ptr [esp+10H]                ; 100BD5DD _ 8B. 7C 24, 10
        add     edi, ecx                                ; 100BD5E1 _ 03. F9
        mov     ecx, edx                                ; 100BD5E3 _ 8B. CA
        shr     ecx, 2                                  ; 100BD5E5 _ C1. E9, 02
        rep movsd                                       ; 100BD5E8 _ F3: A5
        mov     ecx, edx                                ; 100BD5EA _ 8B. CA
        and     ecx, 03H                                ; 100BD5EC _ 83. E1, 03
        rep movsb                                       ; 100BD5EF _ F3: A4
?_25167:pop     edi                                     ; 100BD5F1 _ 5F
        pop     esi                                     ; 100BD5F2 _ 5E
        ret                                             ; 100BD5F3 _ C3

; Filling space: 0CH
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH
        db 0CCH, 0CCH, 0CCH, 0CCH

FUN_100bd600 LABEL NEAR
        mov     ecx, dword ptr [esp+8H]                 ; 100BD600 _ 8B. 4C 24, 08
        push    ebx                                     ; 100BD604 _ 53
        mov     bx, word ptr [ecx]                      ; 100BD605 _ 66: 8B. 19
        push    esi                                     ; 100BD608 _ 56
        mov     eax, dword ptr [esp+14H]                ; 100BD609 _ 8B. 44 24, 14
        push    edi                                     ; 100BD60D _ 57
        mov     ax, word ptr [eax]                      ; 100BD60E _ 66: 8B. 00
        push    ebp                                     ; 100BD611 _ 55
        test    ax, ax                                  ; 100BD612 _ 66: 85. C0
        mov     edx, dword ptr [esp+20H]                ; 100BD615 _ 8B. 54 24, 20
        mov     si, word ptr [edx]                      ; 100BD619 _ 66: 8B. 32
        lea     edi, [ebx+esi]                          ; 100BD61C _ 8D. 3C 33
        jl      ?_25171                                 ; 100BD61F _ 7C, 50
        movsx   ebp, ax                                 ; 100BD621 _ 0F BF. E8
        mov     eax, dword ptr [esp+14H]                ; 100BD624 _ 8B. 44 24, 14
        cmp     dword ptr [eax+8H], ebp                 ; 100BD628 _ 39. 68, 08
        jle     ?_25171                                 ; 100BD62B _ 7E, 44
        test    di, di                                  ; 100BD62D _ 66: 85. FF
        jl      ?_25171                                 ; 100BD630 _ 7C, 3F
        movsx   ebp, bx                                 ; 100BD632 _ 0F BF. EB
        cmp     ebp, dword ptr [eax+4H]                 ; 100BD635 _ 3B. 68, 04
        jge     ?_25171                                 ; 100BD638 _ 7D, 37
        test    bx, bx                                  ; 100BD63A _ 66: 85. DB
        jge     ?_25169                                 ; 100BD63D _ 7D, 0B
        mov     si, di                                  ; 100BD63F _ 66: 8B. F7
        mov     word ptr [edx], di                      ; 100BD642 _ 66: 89. 3A
; Note: Length-changing prefix causes delay on Intel processors
        mov     word ptr [ecx], 0                       ; 100BD645 _ 66: C7. 01, 0000
?_25169:movsx   ecx, di                                 ; 100BD64A _ 0F BF. CF
        mov     eax, dword ptr [eax+4H]                 ; 100BD64D _ 8B. 40, 04
        cmp     ecx, eax                                ; 100BD650 _ 3B. C8
        jle     ?_25170                                 ; 100BD652 _ 7E, 09
        sub     si, di                                  ; 100BD654 _ 66: 2B. F7
        add     si, ax                                  ; 100BD657 _ 66: 03. F0
        mov     word ptr [edx], si                      ; 100BD65A _ 66: 89. 32
?_25170:test    si, si                                  ; 100BD65D _ 66: 85. F6
        mov     eax, 0                                  ; 100BD660 _ B8, 00000000
        jl      ?_25172                                 ; 100BD665 _ 7C, 0C
        pop     ebp                                     ; 100BD667 _ 5D
        mov     eax, 1                                  ; 100BD668 _ B8, 00000001
        pop     edi                                     ; 100BD66D _ 5F
        pop     esi                                     ; 100BD66E _ 5E
        pop     ebx                                     ; 100BD66F _ 5B
        ret                                             ; 100BD670 _ C3

?_25171:xor     eax, eax                                ; 100BD671 _ 33. C0
?_25172:pop     ebp                                     ; 100BD673 _ 5D
        pop     edi                                     ; 100BD674 _ 5F
        pop     esi                                     ; 100BD675 _ 5E
        pop     ebx                                     ; 100BD676 _ 5B
        ret                                             ; 100BD677 _ C3

; Filling space: 8H
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH

FUN_100bd680 LABEL NEAR
        lea     eax, [esp+18H]                          ; 100BD680 _ 8D. 44 24, 18
        push    esi                                     ; 100BD684 _ 56
        lea     ecx, [esp+14H]                          ; 100BD685 _ 8D. 4C 24, 14
        push    eax                                     ; 100BD689 _ 50
        lea     edx, [esp+14H]                          ; 100BD68A _ 8D. 54 24, 14
        push    ecx                                     ; 100BD68E _ 51
        mov     esi, dword ptr [esp+10H]                ; 100BD68F _ 8B. 74 24, 10
        push    edx                                     ; 100BD693 _ 52
        push    esi                                     ; 100BD694 _ 56
        call    FUN_100bd600                            ; 100BD695 _ E8, FFFFFF66
        add     esp, 16                                 ; 100BD69A _ 83. C4, 10
        test    eax, eax                                ; 100BD69D _ 85. C0
        jz      ?_25175                                 ; 100BD69F _ 74, 33
        movsx   eax, word ptr [esp+14H]                 ; 100BD6A1 _ 0F BF. 44 24, 14
        mov     ecx, dword ptr [esi+4H]                 ; 100BD6A6 _ 8B. 4E, 04
        add     ecx, 3                                  ; 100BD6A9 _ 83. C1, 03
        and     ecx, 0FFFFFFFCH                         ; 100BD6AC _ 83. E1, FC
        movsx   edx, word ptr [esp+10H]                 ; 100BD6AF _ 0F BF. 54 24, 10
        imul    ecx, eax                                ; 100BD6B4 _ 0F AF. C8
        add     ecx, edx                                ; 100BD6B7 _ 03. CA
        mov     eax, dword ptr [esp+0CH]                ; 100BD6B9 _ 8B. 44 24, 0C
        add     eax, ecx                                ; 100BD6BD _ 03. C1
        dec     word ptr [esp+1CH]                      ; 100BD6BF _ 66: FF. 4C 24, 1C
        js      ?_25175                                 ; 100BD6C4 _ 78, 0E
        mov     cl, byte ptr [esp+18H]                  ; 100BD6C6 _ 8A. 4C 24, 18
?_25174:mov     byte ptr [eax], cl                      ; 100BD6CA _ 88. 08
        inc     eax                                     ; 100BD6CC _ 40
        dec     word ptr [esp+1CH]                      ; 100BD6CD _ 66: FF. 4C 24, 1C
        jns     ?_25174                                 ; 100BD6D2 _ 79, F6
?_25175:pop     esi                                     ; 100BD6D4 _ 5E
        ret                                             ; 100BD6D5 _ C3

; Filling space: 0AH
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH
        db 0CCH, 0CCH

FUN_100bd6e0 LABEL NEAR
        lea     eax, [esp+18H]                          ; 100BD6E0 _ 8D. 44 24, 18
        push    ebx                                     ; 100BD6E4 _ 53
        lea     ecx, [esp+14H]                          ; 100BD6E5 _ 8D. 4C 24, 14
        push    esi                                     ; 100BD6E9 _ 56
        lea     edx, [esp+14H]                          ; 100BD6EA _ 8D. 54 24, 14
        push    eax                                     ; 100BD6EE _ 50
        mov     esi, dword ptr [esp+10H]                ; 100BD6EF _ 8B. 74 24, 10
        push    ecx                                     ; 100BD6F3 _ 51
        shl     word ptr [esp+28H], 1                   ; 100BD6F4 _ 66: C1. 64 24, 28, 01
        push    edx                                     ; 100BD6FA _ 52
        push    esi                                     ; 100BD6FB _ 56
        call    FUN_100bd600                            ; 100BD6FC _ E8, FFFFFEFF
        add     esp, 16                                 ; 100BD701 _ 83. C4, 10
        test    eax, eax                                ; 100BD704 _ 85. C0
        jz      ?_25179                                 ; 100BD706 _ 74, 52
        mov     dx, word ptr [esp+20H]                  ; 100BD708 _ 66: 8B. 54 24, 20
        mov     ecx, dword ptr [esi+4H]                 ; 100BD70D _ 8B. 4E, 04
        and     dx, 01H                                 ; 100BD710 _ 66: 83. E2, 01
        add     ecx, 3                                  ; 100BD714 _ 83. C1, 03
        movsx   eax, word ptr [esp+18H]                 ; 100BD717 _ 0F BF. 44 24, 18
        movsx   ebx, word ptr [esp+14H]                 ; 100BD71C _ 0F BF. 5C 24, 14
        and     ecx, 0FFFFFFFCH                         ; 100BD721 _ 83. E1, FC
        sar     word ptr [esp+20H], 1                   ; 100BD724 _ 66: C1. 7C 24, 20, 01
        imul    ecx, eax                                ; 100BD72A _ 0F AF. C8
        add     ecx, ebx                                ; 100BD72D _ 03. CB
        mov     eax, dword ptr [esp+10H]                ; 100BD72F _ 8B. 44 24, 10
        add     eax, ecx                                ; 100BD733 _ 03. C1
        mov     bl, byte ptr [esp+1CH]                  ; 100BD735 _ 8A. 5C 24, 1C
        dec     word ptr [esp+20H]                      ; 100BD739 _ 66: FF. 4C 24, 20
        js      ?_25178                                 ; 100BD73E _ 78, 13
?_25177:mov     cx, word ptr [esp+1CH]                  ; 100BD740 _ 66: 8B. 4C 24, 1C
        add     eax, 2                                  ; 100BD745 _ 83. C0, 02
        mov     word ptr [eax-2H], cx                   ; 100BD748 _ 66: 89. 48, FE
        dec     word ptr [esp+20H]                      ; 100BD74C _ 66: FF. 4C 24, 20
        jns     ?_25177                                 ; 100BD751 _ 79, ED
?_25178:test    dx, dx                                  ; 100BD753 _ 66: 85. D2
        jz      ?_25179                                 ; 100BD756 _ 74, 02
        mov     byte ptr [eax], bl                      ; 100BD758 _ 88. 18
?_25179:pop     esi                                     ; 100BD75A _ 5E
        pop     ebx                                     ; 100BD75B _ 5B
        ret                                             ; 100BD75C _ C3

; Filling space: 3H
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH

FUN_100bd760 LABEL NEAR
        mov     eax, dword ptr [esp+18H]                ; 100BD760 _ 8B. 44 24, 18
        sub     esp, 4                                  ; 100BD764 _ 83. EC, 04
; Note: Length-changing prefix causes delay on Intel processors
        mov     word ptr [esp+2H], 0                    ; 100BD767 _ 66: C7. 44 24, 02, 0000
        mov     ecx, dword ptr [esp+14H]                ; 100BD76E _ 8B. 4C 24, 14
        push    ebx                                     ; 100BD772 _ 53
        push    esi                                     ; 100BD773 _ 56
        mov     byte ptr [eax], 0                       ; 100BD774 _ C6. 00, 00
        cmp     word ptr [ecx+6H], 0                    ; 100BD777 _ 66: 83. 79, 06, 00
        push    edi                                     ; 100BD77C _ 57
        push    ebp                                     ; 100BD77D _ 55
        jle     ?_25191                                 ; 100BD77E _ 0F 8E, 000000C1
        mov     esi, dword ptr [esp+18H]                ; 100BD784 _ 8B. 74 24, 18
        mov     edi, dword ptr [esp+1CH]                ; 100BD788 _ 8B. 7C 24, 1C
        mov     ebx, dword ptr [esp+20H]                ; 100BD78C _ 8B. 5C 24, 20
        mov     ebp, dword ptr [esp+28H]                ; 100BD790 _ 8B. 6C 24, 28
?_25181:mov     ecx, ebp                                ; 100BD794 _ 8B. CD
        xor     edx, edx                                ; 100BD796 _ 33. D2
        mov     dx, word ptr [ecx+4H]                   ; 100BD798 _ 66: 8B. 51, 04
        add     ebp, dword ptr [ebp]                    ; 100BD79C _ 03. 6D, 00
        sub     edx, 4                                  ; 100BD79F _ 83. EA, 04
        cmp     edx, 12                                 ; 100BD7A2 _ 83. FA, 0C
        ja      ?_25190                                 ; 100BD7A5 _ 0F 87, 00000082
        xor     eax, eax                                ; 100BD7AB _ 33. C0
        mov     al, byte ptr [?_25193+edx]              ; 100BD7AD _ 8A. 82, 100BD870(d)
        jmp     dword ptr [?_25192+eax*4]               ; 100BD7B3 _ FF. 24 85, 100BD850(d)

?_25182 LABEL NEAR
        add     ecx, 6                                  ; 100BD7BA _ 83. C1, 06
        push    ecx                                     ; 100BD7BD _ 51
        push    esi                                     ; 100BD7BE _ 56
        call    FUN_100bd880                            ; 100BD7BF _ E8, 000000BC
        mov     eax, dword ptr [esp+34H]                ; 100BD7C4 _ 8B. 44 24, 34
        add     esp, 8                                  ; 100BD7C8 _ 83. C4, 08
        mov     byte ptr [eax], 1                       ; 100BD7CB _ C6. 00, 01
        jmp     ?_25190                                 ; 100BD7CE _ EB, 5D

?_25183 LABEL NEAR
        push    ebx                                     ; 100BD7D0 _ 53
        add     ecx, 6                                  ; 100BD7D1 _ 83. C1, 06
        push    ecx                                     ; 100BD7D4 _ 51
        push    edi                                     ; 100BD7D5 _ 57
        push    esi                                     ; 100BD7D6 _ 56
        call    FUN_100bdac0                            ; 100BD7D7 _ E8, 000002E4
        jmp     ?_25189                                 ; 100BD7DC _ EB, 4C

?_25184 LABEL NEAR
        add     ecx, 6                                  ; 100BD7DE _ 83. C1, 06
        push    ecx                                     ; 100BD7E1 _ 51
        push    esi                                     ; 100BD7E2 _ 56
        call    FUN_100bd940                            ; 100BD7E3 _ E8, 00000158
        mov     eax, dword ptr [esp+34H]                ; 100BD7E8 _ 8B. 44 24, 34
        add     esp, 8                                  ; 100BD7EC _ 83. C4, 08
        mov     byte ptr [eax], 1                       ; 100BD7EF _ C6. 00, 01
        jmp     ?_25190                                 ; 100BD7F2 _ EB, 39

?_25185 LABEL NEAR
        push    ebx                                     ; 100BD7F4 _ 53
        add     ecx, 6                                  ; 100BD7F5 _ 83. C1, 06
        push    ecx                                     ; 100BD7F8 _ 51
        push    edi                                     ; 100BD7F9 _ 57
        push    esi                                     ; 100BD7FA _ 56
        call    FUN_100bda10                            ; 100BD7FB _ E8, 00000210
        jmp     ?_25189                                 ; 100BD800 _ EB, 28

?_25186 LABEL NEAR
        push    ebx                                     ; 100BD802 _ 53
        add     ecx, 6                                  ; 100BD803 _ 83. C1, 06
        push    ecx                                     ; 100BD806 _ 51
        push    edi                                     ; 100BD807 _ 57
        push    esi                                     ; 100BD808 _ 56
        call    FUN_100bdc00                            ; 100BD809 _ E8, 000003F2
        jmp     ?_25189                                 ; 100BD80E _ EB, 1A

?_25187 LABEL NEAR
        push    ebx                                     ; 100BD810 _ 53
        add     ecx, 6                                  ; 100BD811 _ 83. C1, 06
        push    ecx                                     ; 100BD814 _ 51
        push    edi                                     ; 100BD815 _ 57
        push    esi                                     ; 100BD816 _ 56
        call    FUN_100bd960                            ; 100BD817 _ E8, 00000144
        jmp     ?_25189                                 ; 100BD81C _ EB, 0C

?_25188 LABEL NEAR
        push    ebx                                     ; 100BD81E _ 53
        add     ecx, 6                                  ; 100BD81F _ 83. C1, 06
        push    ecx                                     ; 100BD822 _ 51
        push    edi                                     ; 100BD823 _ 57
        push    esi                                     ; 100BD824 _ 56
        call    FUN_100bdc90                            ; 100BD825 _ E8, 00000466
?_25189:add     esp, 16                                 ; 100BD82A _ 83. C4, 10

?_25190 LABEL NEAR
        inc     word ptr [esp+12H]                      ; 100BD82D _ 66: FF. 44 24, 12
        mov     eax, dword ptr [esp+24H]                ; 100BD832 _ 8B. 44 24, 24
        mov     cx, word ptr [esp+12H]                  ; 100BD836 _ 66: 8B. 4C 24, 12
        cmp     word ptr [eax+6H], cx                   ; 100BD83B _ 66: 39. 48, 06
        jg      ?_25181                                 ; 100BD83F _ 0F 8F, FFFFFF4F
?_25191:xor     ax, ax                                  ; 100BD845 _ 66: 33. C0
        pop     ebp                                     ; 100BD848 _ 5D
        pop     edi                                     ; 100BD849 _ 5F
        pop     esi                                     ; 100BD84A _ 5E
        pop     ebx                                     ; 100BD84B _ 5B
        add     esp, 4                                  ; 100BD84C _ 83. C4, 04
        ret                                             ; 100BD84F _ C3

?_25192 label dword                                     ; switch/case jump table
        dd ?_25182                                      ; 100BD850 _ 100BD7BA (d)
        dd ?_25183                                      ; 100BD854 _ 100BD7D0 (d)
        dd ?_25184                                      ; 100BD858 _ 100BD7DE (d)
        dd ?_25185                                      ; 100BD85C _ 100BD7F4 (d)
        dd ?_25186                                      ; 100BD860 _ 100BD802 (d)
        dd ?_25187                                      ; 100BD864 _ 100BD810 (d)
        dd ?_25188                                      ; 100BD868 _ 100BD81E (d)
        dd ?_25190                                      ; 100BD86C _ 100BD82D (d)

?_25193 db 00H, 07H, 07H, 01H, 07H, 07H, 07H, 02H       ; 100BD870 _ ........
        db 03H, 04H, 07H, 05H, 06H, 0CCH, 0CCH, 0CCH    ; 100BD878 _ ........

FUN_100bd880 LABEL NEAR
        mov     eax, dword ptr [esp+8H]                 ; 100BD880 _ 8B. 44 24, 08
        mov     ecx, dword ptr [esp+4H]                 ; 100BD884 _ 8B. 4C 24, 04
        push    eax                                     ; 100BD888 _ 50
        push    ecx                                     ; 100BD889 _ 51
        call    FUN_100bd8a0                            ; 100BD88A _ E8, 00000011
        add     esp, 8                                  ; 100BD88F _ 83. C4, 08
        ret                                             ; 100BD892 _ C3

; Filling space: 0DH
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH

FUN_100bd8a0 LABEL NEAR
        mov     eax, dword ptr [esp+8H]                 ; 100BD8A0 _ 8B. 44 24, 08
        push    ebx                                     ; 100BD8A4 _ 53
        mov     bx, word ptr [eax]                      ; 100BD8A5 _ 66: 8B. 18
        push    esi                                     ; 100BD8A8 _ 56
        xor     si, si                                  ; 100BD8A9 _ 66: 33. F6
        push    edi                                     ; 100BD8AC _ 57
        dec     bx                                      ; 100BD8AD _ 66: 4B
        push    ebp                                     ; 100BD8AF _ 55
        lea     edi, [eax+2H]                           ; 100BD8B0 _ 8D. 78, 02
        js      ?_25198                                 ; 100BD8B3 _ 78, 36
?_25196:movzx   ax, byte ptr [edi]                      ; 100BD8B5 _ 66: 0F B6. 07
        movzx   bp, byte ptr [edi+1H]                   ; 100BD8B9 _ 66: 0F B6. 6F, 01
        add     si, ax                                  ; 100BD8BE _ 66: 03. F0
        inc     edi                                     ; 100BD8C1 _ 47
        inc     edi                                     ; 100BD8C2 _ 47
        test    bp, bp                                  ; 100BD8C3 _ 66: 85. ED
        jnz     ?_25197                                 ; 100BD8C6 _ 75, 04
; Note: Length-changing prefix causes delay on Intel processors
        mov     bp, 256                                 ; 100BD8C8 _ 66: BD, 0100
?_25197:mov     eax, dword ptr [esp+14H]                ; 100BD8CC _ 8B. 44 24, 14
        push    ebp                                     ; 100BD8D0 _ 55
        push    esi                                     ; 100BD8D1 _ 56
        push    edi                                     ; 100BD8D2 _ 57
        add     si, bp                                  ; 100BD8D3 _ 66: 03. F5
        push    eax                                     ; 100BD8D6 _ 50
        call    FUN_100bd8f0                            ; 100BD8D7 _ E8, 00000014
        movsx   eax, bp                                 ; 100BD8DC _ 0F BF. C5
        add     esp, 16                                 ; 100BD8DF _ 83. C4, 10
        lea     ecx, [eax+eax*2]                        ; 100BD8E2 _ 8D. 0C 40
        add     edi, ecx                                ; 100BD8E5 _ 03. F9
        dec     bx                                      ; 100BD8E7 _ 66: 4B
        jns     ?_25196                                 ; 100BD8E9 _ 79, CA
?_25198:pop     ebp                                     ; 100BD8EB _ 5D
        pop     edi                                     ; 100BD8EC _ 5F
        pop     esi                                     ; 100BD8ED _ 5E
        pop     ebx                                     ; 100BD8EE _ 5B
        ret                                             ; 100BD8EF _ C3

FUN_100bd8f0 LABEL NEAR
        mov     dx, word ptr [esp+10H]                  ; 100BD8F0 _ 66: 8B. 54 24, 10
        push    esi                                     ; 100BD8F5 _ 56
        movsx   ecx, word ptr [esp+10H]                 ; 100BD8F6 _ 0F BF. 4C 24, 10
        shl     ecx, 2                                  ; 100BD8FB _ C1. E1, 02
        mov     eax, dword ptr [esp+8H]                 ; 100BD8FE _ 8B. 44 24, 08
        add     ecx, dword ptr [eax]                    ; 100BD902 _ 03. 08
        lea     esi, [ecx+eax]                          ; 100BD904 _ 8D. 34 01
        mov     ax, dx                                  ; 100BD907 _ 66: 8B. C2
        dec     dx                                      ; 100BD90A _ 66: 4A
        test    ax, ax                                  ; 100BD90C _ 66: 85. C0
        jz      ?_25201                                 ; 100BD90F _ 74, 25
        mov     eax, dword ptr [esp+0CH]                ; 100BD911 _ 8B. 44 24, 0C
?_25200:mov     cl, byte ptr [eax]                      ; 100BD915 _ 8A. 08
        add     esi, 4                                  ; 100BD917 _ 83. C6, 04
        add     eax, 3                                  ; 100BD91A _ 83. C0, 03
        mov     byte ptr [esi-2H], cl                   ; 100BD91D _ 88. 4E, FE
        mov     cl, byte ptr [eax-2H]                   ; 100BD920 _ 8A. 48, FE
        mov     byte ptr [esi-3H], cl                   ; 100BD923 _ 88. 4E, FD
        mov     cl, byte ptr [eax-1H]                   ; 100BD926 _ 8A. 48, FF
        mov     byte ptr [esi-4H], cl                   ; 100BD929 _ 88. 4E, FC
        mov     cx, dx                                  ; 100BD92C _ 66: 8B. CA
        dec     dx                                      ; 100BD92F _ 66: 4A
        test    cx, cx                                  ; 100BD931 _ 66: 85. C9
        jnz     ?_25200                                 ; 100BD934 _ 75, DF
?_25201:pop     esi                                     ; 100BD936 _ 5E
        ret                                             ; 100BD937 _ C3

; Filling space: 8H
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH

FUN_100bd940 LABEL NEAR
        mov     eax, dword ptr [esp+8H]                 ; 100BD940 _ 8B. 44 24, 08
        mov     ecx, dword ptr [esp+4H]                 ; 100BD944 _ 8B. 4C 24, 04
        push    eax                                     ; 100BD948 _ 50
        push    ecx                                     ; 100BD949 _ 51
        call    FUN_100bd8a0                            ; 100BD94A _ E8, FFFFFF51
        add     esp, 8                                  ; 100BD94F _ 83. C4, 08
        ret                                             ; 100BD952 _ C3

; Filling space: 0DH
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH

FUN_100bd960 LABEL NEAR
        mov     eax, dword ptr [esp+10H]                ; 100BD960 _ 8B. 44 24, 10
        sub     esp, 8                                  ; 100BD964 _ 83. EC, 08
        mov     dx, word ptr [eax+8H]                   ; 100BD967 _ 66: 8B. 50, 08
        push    ebx                                     ; 100BD96B _ 53
        mov     ecx, dword ptr [esp+18H]                ; 100BD96C _ 8B. 4C 24, 18
        push    esi                                     ; 100BD970 _ 56
        push    edi                                     ; 100BD971 _ 57
        push    ebp                                     ; 100BD972 _ 55
        mov     di, word ptr [eax+0AH]                  ; 100BD973 _ 66: 8B. 78, 0A
        mov     eax, dword ptr [esp+1CH]                ; 100BD977 _ 8B. 44 24, 1C
        mov     esi, dword ptr [eax+4H]                 ; 100BD97B _ 8B. 70, 04
        movsx   eax, di                                 ; 100BD97E _ 0F BF. C7
        add     esi, 3                                  ; 100BD981 _ 83. C6, 03
        dec     eax                                     ; 100BD984 _ 48
        and     esi, 0FFFFFFFCH                         ; 100BD985 _ 83. E6, FC
        imul    esi, eax                                ; 100BD988 _ 0F AF. F0
        add     esi, dword ptr [esp+20H]                ; 100BD98B _ 03. 74 24, 20
        dec     di                                      ; 100BD98F _ 66: 4F
        mov     word ptr [esp+12H], di                  ; 100BD991 _ 66: 89. 7C 24, 12
        js      ?_25212                                 ; 100BD996 _ 78, 64
        movsx   eax, dx                                 ; 100BD998 _ 0F BF. C2
        mov     dword ptr [esp+14H], eax                ; 100BD99B _ 89. 44 24, 14
?_25204:xor     di, di                                  ; 100BD99F _ 66: 33. FF
        inc     ecx                                     ; 100BD9A2 _ 41
        test    dx, dx                                  ; 100BD9A3 _ 66: 85. D2
        jle     ?_25211                                 ; 100BD9A6 _ 7E, 3A
?_25205:mov     al, byte ptr [ecx]                      ; 100BD9A8 _ 8A. 01
        inc     ecx                                     ; 100BD9AA _ 41
        test    al, al                                  ; 100BD9AB _ 84. C0
        jl      ?_25208                                 ; 100BD9AD _ 7C, 13
        jle     ?_25207                                 ; 100BD9AF _ 7E, 0E
        movsx   bp, al                                  ; 100BD9B1 _ 66: 0F BE. E8
?_25206:mov     bl, byte ptr [ecx]                      ; 100BD9B5 _ 8A. 19
        inc     esi                                     ; 100BD9B7 _ 46
        dec     bp                                      ; 100BD9B8 _ 66: 4D
        mov     byte ptr [esi-1H], bl                   ; 100BD9BA _ 88. 5E, FF
        jnz     ?_25206                                 ; 100BD9BD _ 75, F6
?_25207:inc     ecx                                     ; 100BD9BF _ 41
        jmp     ?_25210                                 ; 100BD9C0 _ EB, 14

?_25208:neg     al                                      ; 100BD9C2 _ F6. D8
        test    al, al                                  ; 100BD9C4 _ 84. C0
        jle     ?_25210                                 ; 100BD9C6 _ 7E, 0E
        movsx   bp, al                                  ; 100BD9C8 _ 66: 0F BE. E8
?_25209:mov     bl, byte ptr [ecx]                      ; 100BD9CC _ 8A. 19
        inc     ecx                                     ; 100BD9CE _ 41
        mov     byte ptr [esi], bl                      ; 100BD9CF _ 88. 1E
        inc     esi                                     ; 100BD9D1 _ 46
        dec     bp                                      ; 100BD9D2 _ 66: 4D
        jnz     ?_25209                                 ; 100BD9D4 _ 75, F6
?_25210:movsx   ax, al                                  ; 100BD9D6 _ 66: 0F BE. C0
        add     di, ax                                  ; 100BD9DA _ 66: 03. F8
        cmp     dx, di                                  ; 100BD9DD _ 66: 3B. D7
        jg      ?_25205                                 ; 100BD9E0 _ 7F, C6
?_25211:mov     eax, dword ptr [esp+1CH]                ; 100BD9E2 _ 8B. 44 24, 1C
        mov     eax, dword ptr [eax+4H]                 ; 100BD9E6 _ 8B. 40, 04
        add     eax, 3                                  ; 100BD9E9 _ 83. C0, 03
        and     eax, 0FFFFFFFCH                         ; 100BD9EC _ 83. E0, FC
        add     eax, dword ptr [esp+14H]                ; 100BD9EF _ 03. 44 24, 14
        sub     esi, eax                                ; 100BD9F3 _ 2B. F0
        dec     word ptr [esp+12H]                      ; 100BD9F5 _ 66: FF. 4C 24, 12
        jns     ?_25204                                 ; 100BD9FA _ 79, A3
?_25212:pop     ebp                                     ; 100BD9FC _ 5D
        pop     edi                                     ; 100BD9FD _ 5F
        pop     esi                                     ; 100BD9FE _ 5E
        pop     ebx                                     ; 100BD9FF _ 5B
        add     esp, 8                                  ; 100BDA00 _ 83. C4, 08
        ret                                             ; 100BDA03 _ C3

; Filling space: 0CH
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH
        db 0CCH, 0CCH, 0CCH, 0CCH

FUN_100bda10 LABEL NEAR
        mov     ecx, dword ptr [esp+0CH]                ; 100BDA10 _ 8B. 4C 24, 0C
        sub     esp, 4                                  ; 100BDA14 _ 83. EC, 04
        mov     eax, dword ptr [esp+14H]                ; 100BDA17 _ 8B. 44 24, 14
        push    ebx                                     ; 100BDA1B _ 53
        mov     ax, word ptr [eax+0AH]                  ; 100BDA1C _ 66: 8B. 40, 0A
        push    esi                                     ; 100BDA20 _ 56
        sub     ax, word ptr [ecx]                      ; 100BDA21 _ 66: 2B. 01
        push    edi                                     ; 100BDA24 _ 57
        dec     ax                                      ; 100BDA25 _ 66: 48
        push    ebp                                     ; 100BDA27 _ 55
        mov     word ptr [esp+12H], ax                  ; 100BDA28 _ 66: 89. 44 24, 12
        lea     esi, [ecx+4H]                           ; 100BDA2D _ 8D. 71, 04
        mov     ax, word ptr [ecx+2H]                   ; 100BDA30 _ 66: 8B. 41, 02
        dec     ax                                      ; 100BDA34 _ 66: 48
        mov     word ptr [esp+10H], ax                  ; 100BDA36 _ 66: 89. 44 24, 10
        js      ?_25219                                 ; 100BDA3B _ 78, 78
?_25214:xor     di, di                                  ; 100BDA3D _ 66: 33. FF
        mov     bl, byte ptr [esi]                      ; 100BDA40 _ 8A. 1E
        inc     esi                                     ; 100BDA42 _ 46
        test    bl, bl                                  ; 100BDA43 _ 84. DB
        jz      ?_25218                                 ; 100BDA45 _ 74, 62
?_25215:movzx   ax, byte ptr [esi]                      ; 100BDA47 _ 66: 0F B6. 06
        add     di, ax                                  ; 100BDA4B _ 66: 03. F8
        inc     esi                                     ; 100BDA4E _ 46
        mov     al, byte ptr [esi]                      ; 100BDA4F _ 8A. 06
        inc     esi                                     ; 100BDA51 _ 46
        test    al, al                                  ; 100BDA52 _ 84. C0
        jge     ?_25216                                 ; 100BDA54 _ 7D, 27
        mov     ecx, esi                                ; 100BDA56 _ 8B. CE
        mov     edx, dword ptr [esp+1CH]                ; 100BDA58 _ 8B. 54 24, 1C
        neg     al                                      ; 100BDA5C _ F6. D8
        movsx   bp, al                                  ; 100BDA5E _ 66: 0F BE. E8
        inc     esi                                     ; 100BDA62 _ 46
        push    ebp                                     ; 100BDA63 _ 55
        mov     al, byte ptr [ecx]                      ; 100BDA64 _ 8A. 01
        mov     ecx, dword ptr [esp+16H]                ; 100BDA66 _ 8B. 4C 24, 16
        push    eax                                     ; 100BDA6A _ 50
        push    ecx                                     ; 100BDA6B _ 51
        mov     eax, dword ptr [esp+24H]                ; 100BDA6C _ 8B. 44 24, 24
        push    edi                                     ; 100BDA70 _ 57
        push    edx                                     ; 100BDA71 _ 52
        push    eax                                     ; 100BDA72 _ 50
        call    FUN_100bd680                            ; 100BDA73 _ E8, FFFFFC08
        add     esp, 24                                 ; 100BDA78 _ 83. C4, 18
        jmp     ?_25217                                 ; 100BDA7B _ EB, 23

?_25216:mov     ecx, dword ptr [esp+1CH]                ; 100BDA7D _ 8B. 4C 24, 1C
        mov     edx, dword ptr [esp+18H]                ; 100BDA81 _ 8B. 54 24, 18
        movsx   bp, al                                  ; 100BDA85 _ 66: 0F BE. E8
        mov     eax, dword ptr [esp+12H]                ; 100BDA89 _ 8B. 44 24, 12
        push    ebp                                     ; 100BDA8D _ 55
        push    esi                                     ; 100BDA8E _ 56
        push    eax                                     ; 100BDA8F _ 50
        push    edi                                     ; 100BDA90 _ 57
        push    ecx                                     ; 100BDA91 _ 51
        push    edx                                     ; 100BDA92 _ 52
        call    FUN_100bd580                            ; 100BDA93 _ E8, FFFFFAE8
        movsx   ecx, bp                                 ; 100BDA98 _ 0F BF. CD
        add     esp, 24                                 ; 100BDA9B _ 83. C4, 18
        add     esi, ecx                                ; 100BDA9E _ 03. F1
?_25217:add     di, bp                                  ; 100BDAA0 _ 66: 03. FD
        dec     bl                                      ; 100BDAA3 _ FE. CB
        test    bl, bl                                  ; 100BDAA5 _ 84. DB
        jnz     ?_25215                                 ; 100BDAA7 _ 75, 9E
?_25218:dec     word ptr [esp+12H]                      ; 100BDAA9 _ 66: FF. 4C 24, 12
        dec     word ptr [esp+10H]                      ; 100BDAAE _ 66: FF. 4C 24, 10
        jns     ?_25214                                 ; 100BDAB3 _ 79, 88
?_25219:pop     ebp                                     ; 100BDAB5 _ 5D
        pop     edi                                     ; 100BDAB6 _ 5F
        pop     esi                                     ; 100BDAB7 _ 5E
        pop     ebx                                     ; 100BDAB8 _ 5B
        add     esp, 4                                  ; 100BDAB9 _ 83. C4, 04
        ret                                             ; 100BDABC _ C3

; Filling space: 3H
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH

FUN_100bdac0 LABEL NEAR
        mov     edx, dword ptr [esp+10H]                ; 100BDAC0 _ 8B. 54 24, 10
        sub     esp, 8                                  ; 100BDAC4 _ 83. EC, 08
        mov     ax, word ptr [edx+8H]                   ; 100BDAC7 _ 66: 8B. 42, 08
        push    ebx                                     ; 100BDACB _ 53
        dec     ax                                      ; 100BDACC _ 66: 48
        push    esi                                     ; 100BDACE _ 56
        mov     word ptr [esp+8H], ax                   ; 100BDACF _ 66: 89. 44 24, 08
        push    edi                                     ; 100BDAD4 _ 57
        mov     si, word ptr [edx+0AH]                  ; 100BDAD5 _ 66: 8B. 72, 0A
        push    ebp                                     ; 100BDAD9 _ 55
        dec     si                                      ; 100BDADA _ 66: 4E
        mov     ecx, dword ptr [esp+24H]                ; 100BDADC _ 8B. 4C 24, 24
        mov     bx, word ptr [ecx]                      ; 100BDAE0 _ 66: 8B. 19
        add     ecx, 2                                  ; 100BDAE3 _ 83. C1, 02
        mov     word ptr [esp+12H], bx                  ; 100BDAE6 _ 66: 89. 5C 24, 12
        mov     dword ptr [esp+14H], ecx                ; 100BDAEB _ 89. 4C 24, 14
?_25221:mov     eax, dword ptr [esp+14H]                ; 100BDAEF _ 8B. 44 24, 14
        mov     bx, word ptr [eax]                      ; 100BDAF3 _ 66: 8B. 18
        add     dword ptr [esp+14H], 2                  ; 100BDAF6 _ 83. 44 24, 14, 02
        test    bx, bx                                  ; 100BDAFB _ 66: 85. DB
        jge     ?_25223                                 ; 100BDAFE _ 7D, 49
        test    bh, 40H                                 ; 100BDB00 _ F6. C7, 40
        jz      ?_25222                                 ; 100BDB03 _ 74, 05
        add     si, bx                                  ; 100BDB05 _ 66: 03. F3
        jmp     ?_25221                                 ; 100BDB08 _ EB, E5

?_25222:mov     eax, dword ptr [esp+10H]                ; 100BDB0A _ 8B. 44 24, 10
        push    ebx                                     ; 100BDB0E _ 53
        mov     ecx, dword ptr [esp+24H]                ; 100BDB0F _ 8B. 4C 24, 24
        push    esi                                     ; 100BDB13 _ 56
        mov     edx, dword ptr [esp+24H]                ; 100BDB14 _ 8B. 54 24, 24
        push    eax                                     ; 100BDB18 _ 50
        push    ecx                                     ; 100BDB19 _ 51
        push    edx                                     ; 100BDB1A _ 52
        call    FUN_100bd530                            ; 100BDB1B _ E8, FFFFFA10
        mov     ecx, dword ptr [esp+28H]                ; 100BDB20 _ 8B. 4C 24, 28
        add     esp, 20                                 ; 100BDB24 _ 83. C4, 14
        mov     bx, word ptr [ecx]                      ; 100BDB27 _ 66: 8B. 19
        add     dword ptr [esp+14H], 2                  ; 100BDB2A _ 83. 44 24, 14, 02
        test    bx, bx                                  ; 100BDB2F _ 66: 85. DB
        jnz     ?_25223                                 ; 100BDB32 _ 75, 15
        dec     si                                      ; 100BDB34 _ 66: 4E
        dec     word ptr [esp+12H]                      ; 100BDB36 _ 66: FF. 4C 24, 12
        cmp     word ptr [esp+12H], 0                   ; 100BDB3B _ 66: 83. 7C 24, 12, 00
        jle     ?_25226                                 ; 100BDB41 _ 0F 8E, 000000AE
        jmp     ?_25221                                 ; 100BDB47 _ EB, A6

?_25223:xor     di, di                                  ; 100BDB49 _ 66: 33. FF
?_25224:mov     ecx, dword ptr [esp+14H]                ; 100BDB4C _ 8B. 4C 24, 14
        movzx   ax, byte ptr [ecx]                      ; 100BDB50 _ 66: 0F B6. 01
        add     di, ax                                  ; 100BDB54 _ 66: 03. F8
        inc     dword ptr [esp+14H]                     ; 100BDB57 _ FF. 44 24, 14
        mov     ecx, dword ptr [esp+14H]                ; 100BDB5B _ 8B. 4C 24, 14
        movsx   bp, byte ptr [ecx]                      ; 100BDB5F _ 66: 0F BE. 29
        add     bp, bp                                  ; 100BDB63 _ 66: 03. ED
        inc     dword ptr [esp+14H]                     ; 100BDB66 _ FF. 44 24, 14
        test    bp, bp                                  ; 100BDB6A _ 66: 85. ED
        jl      ?_25225                                 ; 100BDB6D _ 7C, 3C
        mov     eax, dword ptr [esp+14H]                ; 100BDB6F _ 8B. 44 24, 14
        push    ebp                                     ; 100BDB73 _ 55
        mov     ecx, dword ptr [esp+24H]                ; 100BDB74 _ 8B. 4C 24, 24
        push    eax                                     ; 100BDB78 _ 50
        mov     edx, dword ptr [esp+24H]                ; 100BDB79 _ 8B. 54 24, 24
        push    esi                                     ; 100BDB7D _ 56
        push    edi                                     ; 100BDB7E _ 57
        push    ecx                                     ; 100BDB7F _ 51
        add     di, bp                                  ; 100BDB80 _ 66: 03. FD
        push    edx                                     ; 100BDB83 _ 52
        call    FUN_100bd580                            ; 100BDB84 _ E8, FFFFF9F7
        movsx   ecx, bp                                 ; 100BDB89 _ 0F BF. CD
        add     dword ptr [esp+2CH], ecx                ; 100BDB8C _ 01. 4C 24, 2C
        add     esp, 24                                 ; 100BDB90 _ 83. C4, 18
        dec     bx                                      ; 100BDB93 _ 66: 4B
        jnz     ?_25224                                 ; 100BDB95 _ 75, B5
        dec     si                                      ; 100BDB97 _ 66: 4E
        dec     word ptr [esp+12H]                      ; 100BDB99 _ 66: FF. 4C 24, 12
        cmp     word ptr [esp+12H], 0                   ; 100BDB9E _ 66: 83. 7C 24, 12, 00
        jle     ?_25226                                 ; 100BDBA4 _ 7E, 4F
        jmp     ?_25221                                 ; 100BDBA6 _ E9, FFFFFF44

?_25225:mov     eax, dword ptr [esp+14H]                ; 100BDBAB _ 8B. 44 24, 14
        mov     edx, dword ptr [esp+20H]                ; 100BDBAF _ 8B. 54 24, 20
        neg     bp                                      ; 100BDBB3 _ 66: F7. DD
        add     dword ptr [esp+14H], 2                  ; 100BDBB6 _ 83. 44 24, 14, 02
        mov     cx, bp                                  ; 100BDBBB _ 66: 8B. CD
        sar     cx, 1                                   ; 100BDBBE _ 66: C1. F9, 01
        mov     ax, word ptr [eax]                      ; 100BDBC2 _ 66: 8B. 00
        push    ecx                                     ; 100BDBC5 _ 51
        mov     ecx, dword ptr [esp+20H]                ; 100BDBC6 _ 8B. 4C 24, 20
        push    eax                                     ; 100BDBCA _ 50
        push    esi                                     ; 100BDBCB _ 56
        push    edi                                     ; 100BDBCC _ 57
        add     di, bp                                  ; 100BDBCD _ 66: 03. FD
        push    edx                                     ; 100BDBD0 _ 52
        push    ecx                                     ; 100BDBD1 _ 51
        call    FUN_100bd6e0                            ; 100BDBD2 _ E8, FFFFFB09
        add     esp, 24                                 ; 100BDBD7 _ 83. C4, 18
        dec     bx                                      ; 100BDBDA _ 66: 4B
        jne     ?_25224                                 ; 100BDBDC _ 0F 85, FFFFFF6A
        dec     si                                      ; 100BDBE2 _ 66: 4E
        dec     word ptr [esp+12H]                      ; 100BDBE4 _ 66: FF. 4C 24, 12
        cmp     word ptr [esp+12H], 0                   ; 100BDBE9 _ 66: 83. 7C 24, 12, 00
        jg      ?_25221                                 ; 100BDBEF _ 0F 8F, FFFFFEFA
?_25226:pop     ebp                                     ; 100BDBF5 _ 5D
        pop     edi                                     ; 100BDBF6 _ 5F
        pop     esi                                     ; 100BDBF7 _ 5E
        pop     ebx                                     ; 100BDBF8 _ 5B
        add     esp, 8                                  ; 100BDBF9 _ 83. C4, 08
        ret                                             ; 100BDBFC _ C3

; Filling space: 3H
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH

FUN_100bdc00 LABEL NEAR
        mov     eax, dword ptr [esp+10H]                ; 100BDC00 _ 8B. 44 24, 10
        sub     esp, 8                                  ; 100BDC04 _ 83. EC, 08
        mov     cx, word ptr [eax+8H]                   ; 100BDC07 _ 66: 8B. 48, 08
        push    ebx                                     ; 100BDC0B _ 53
        mov     word ptr [esp+6H], cx                   ; 100BDC0C _ 66: 89. 4C 24, 06
        push    esi                                     ; 100BDC11 _ 56
        push    edi                                     ; 100BDC12 _ 57
        xor     ecx, ecx                                ; 100BDC13 _ 33. C9
        mov     byte ptr [esp+0DH], cl                  ; 100BDC15 _ 88. 4C 24, 0D
        push    ebp                                     ; 100BDC19 _ 55
        mov     bp, word ptr [eax+0AH]                  ; 100BDC1A _ 66: 8B. 68, 0A
        mov     byte ptr [esp+10H], cl                  ; 100BDC1E _ 88. 4C 24, 10
        dec     bp                                      ; 100BDC22 _ 66: 4D
        js      ?_25230                                 ; 100BDC24 _ 78, 56
        movsx   eax, word ptr [esp+12H]                 ; 100BDC26 _ 0F BF. 44 24, 12
        mov     si, word ptr [esp+12H]                  ; 100BDC2B _ 66: 8B. 74 24, 12
        mov     edi, dword ptr [esp+1CH]                ; 100BDC30 _ 8B. 7C 24, 1C
        cdq                                             ; 100BDC34 _ 99
        and     si, 01H                                 ; 100BDC35 _ 66: 83. E6, 01
        sub     eax, edx                                ; 100BDC39 _ 2B. C2
        sar     eax, 1                                  ; 100BDC3B _ C1. F8, 01
        mov     ebx, dword ptr [esp+20H]                ; 100BDC3E _ 8B. 5C 24, 20
        mov     word ptr [esp+14H], ax                  ; 100BDC42 _ 66: 89. 44 24, 14
?_25228:mov     eax, dword ptr [esp+14H]                ; 100BDC47 _ 8B. 44 24, 14
        mov     ecx, dword ptr [esp+10H]                ; 100BDC4B _ 8B. 4C 24, 10
        push    eax                                     ; 100BDC4F _ 50
        push    ecx                                     ; 100BDC50 _ 51
        push    ebp                                     ; 100BDC51 _ 55
        push    0                                       ; 100BDC52 _ 6A, 00
        push    ebx                                     ; 100BDC54 _ 53
        push    edi                                     ; 100BDC55 _ 57
        call    FUN_100bd6e0                            ; 100BDC56 _ E8, FFFFFA85
        add     esp, 24                                 ; 100BDC5B _ 83. C4, 18
        test    si, si                                  ; 100BDC5E _ 66: 85. F6
        jz      ?_25229                                 ; 100BDC61 _ 74, 15
        mov     ax, word ptr [esp+12H]                  ; 100BDC63 _ 66: 8B. 44 24, 12
        push    0                                       ; 100BDC68 _ 6A, 00
        dec     ax                                      ; 100BDC6A _ 66: 48
        push    ebp                                     ; 100BDC6C _ 55
        push    eax                                     ; 100BDC6D _ 50
        push    ebx                                     ; 100BDC6E _ 53
        push    edi                                     ; 100BDC6F _ 57
        call    FUN_100bd530                            ; 100BDC70 _ E8, FFFFF8BB
        add     esp, 20                                 ; 100BDC75 _ 83. C4, 14
?_25229:dec     bp                                      ; 100BDC78 _ 66: 4D
        jns     ?_25228                                 ; 100BDC7A _ 79, CB
?_25230:pop     ebp                                     ; 100BDC7C _ 5D
        pop     edi                                     ; 100BDC7D _ 5F
        pop     esi                                     ; 100BDC7E _ 5E
        pop     ebx                                     ; 100BDC7F _ 5B
        add     esp, 8                                  ; 100BDC80 _ 83. C4, 08
        ret                                             ; 100BDC83 _ C3

; Filling space: 0CH
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH
        db 0CCH, 0CCH, 0CCH, 0CCH

FUN_100bdc90 LABEL NEAR
        mov     eax, dword ptr [esp+10H]                ; 100BDC90 _ 8B. 44 24, 10
        sub     esp, 4                                  ; 100BDC94 _ 83. EC, 04
        push    ebx                                     ; 100BDC97 _ 53
        push    esi                                     ; 100BDC98 _ 56
        mov     bx, word ptr [eax+0AH]                  ; 100BDC99 _ 66: 8B. 58, 0A
        push    edi                                     ; 100BDC9D _ 57
        mov     di, word ptr [eax+8H]                   ; 100BDC9E _ 66: 8B. 78, 08
        push    ebp                                     ; 100BDCA2 _ 55
        dec     bx                                      ; 100BDCA3 _ 66: 4B
        js      ?_25233                                 ; 100BDCA5 _ 78, 2A
        mov     esi, dword ptr [esp+18H]                ; 100BDCA7 _ 8B. 74 24, 18
        mov     ebp, dword ptr [esp+20H]                ; 100BDCAB _ 8B. 6C 24, 20
        movsx   eax, di                                 ; 100BDCAF _ 0F BF. C7
        mov     dword ptr [esp+10H], eax                ; 100BDCB2 _ 89. 44 24, 10
?_25232:mov     eax, dword ptr [esp+1CH]                ; 100BDCB6 _ 8B. 44 24, 1C
        push    edi                                     ; 100BDCBA _ 57
        push    ebp                                     ; 100BDCBB _ 55
        push    ebx                                     ; 100BDCBC _ 53
        push    0                                       ; 100BDCBD _ 6A, 00
        push    eax                                     ; 100BDCBF _ 50
        push    esi                                     ; 100BDCC0 _ 56
        call    FUN_100bd580                            ; 100BDCC1 _ E8, FFFFF8BA
        add     ebp, dword ptr [esp+28H]                ; 100BDCC6 _ 03. 6C 24, 28
        add     esp, 24                                 ; 100BDCCA _ 83. C4, 18
        dec     bx                                      ; 100BDCCD _ 66: 4B
        jns     ?_25232                                 ; 100BDCCF _ 79, E5
?_25233:pop     ebp                                     ; 100BDCD1 _ 5D
        pop     edi                                     ; 100BDCD2 _ 5F
        pop     esi                                     ; 100BDCD3 _ 5E
        pop     ebx                                     ; 100BDCD4 _ 5B
        add     esp, 4                                  ; 100BDCD5 _ 83. C4, 04
        ret                                             ; 100BDCD8 _ C3

; Filling space: 7H
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH, 0CCH

DecodeFLCFrame LABEL NEAR
        mov     ecx, dword ptr [esp+10H]                ; 100BDCE0 _ 8B. 4C 24, 10
; Note: Length-changing prefix causes delay on Intel processors
        cmp     word ptr [ecx+4H], -3590                ; 100BDCE4 _ 66: 81. 79, 04, F1FA
        jnz     ?_25235                                 ; 100BDCEA _ 75, 21
        mov     eax, dword ptr [esp+14H]                ; 100BDCEC _ 8B. 44 24, 14
        lea     edx, [ecx+10H]                          ; 100BDCF0 _ 8D. 51, 10
        push    eax                                     ; 100BDCF3 _ 50
        push    edx                                     ; 100BDCF4 _ 52
        mov     eax, dword ptr [esp+10H]                ; 100BDCF5 _ 8B. 44 24, 10
        push    ecx                                     ; 100BDCF9 _ 51
        mov     ecx, dword ptr [esp+18H]                ; 100BDCFA _ 8B. 4C 24, 18
        mov     edx, dword ptr [esp+10H]                ; 100BDCFE _ 8B. 54 24, 10
        push    ecx                                     ; 100BDD02 _ 51
        push    eax                                     ; 100BDD03 _ 50
        push    edx                                     ; 100BDD04 _ 52
        call    FUN_100bd760                            ; 100BDD05 _ E8, FFFFFA56
        add     esp, 24                                 ; 100BDD0A _ 83. C4, 18
?_25235:ret                                             ; 100BDD0D _ C3

; Filling space: 2H
; Filler type: INT 3 Debug breakpoint
        db 0CCH, 0CCH

EndOfSection LABEL NEAR

.text ENDS

END
