    ORG 100H                      

.DATA
     
MESSAGE DB "MESSAGE: $"  
MESSAGE2 DB " CIPHER: $"       
MESSAGE3 DB " OUTPUT: $"
     
SBOX   DB  063H, 07cH, 077H, 07bH, 0f2H, 06bH, 06fH, 0c5H, 030H, 001H, 067H, 02bH, 0feH, 0d7H, 0abH, 076H,  ;INPUT[ROW*16 + COLUMN] VIP
       DB  0caH, 082H, 0c9H, 07dH, 0faH, 059H, 047H, 0f0H, 0adH, 0d4H, 0a2H, 0afH, 09cH, 0a4H, 072H, 0c0H,
       DB  0b7H, 0fdH, 093H, 026H, 036H, 03fH, 0f7H, 0ccH, 034H, 0a5H, 0e5H, 0f1H, 071H, 0d8H, 031H, 015H,
       DB  004H, 0c7H, 023H, 0c3H, 018H, 096H, 005H, 09aH, 007H, 012H, 080H, 0e2H, 0ebH, 027H, 0b2H, 075H,
       DB  009H, 083H, 02cH, 01aH, 01bH, 06eH, 05aH, 0a0H, 052H, 03bH, 0d6H, 0b3H, 029H, 0e3H, 02fH, 084H, 
       
       DB  053H, 0d1H, 000H, 0edH, 020H, 0fcH, 0b1H, 05bH, 06aH, 0cbH, 0beH, 039H, 04aH, 04cH, 058H, 0cfH, 
       
       DB  0d0H, 0efH, 0aaH, 0fbH, 043H, 04dH, 033H, 085H, 045H, 0f9H, 002H, 07fH, 050H, 03cH, 09fH, 0a8H,
       DB  051H, 0a3H, 040H, 08fH, 092H, 09dH, 038H, 0f5H, 0bcH, 0b6H, 0daH, 021H, 010H, 0ffH, 0f3H, 0d2H,
       DB  0cdH, 00cH, 013H, 0ecH, 05fH, 097H, 044H, 017H, 0c4H, 0a7H, 07eH, 03dH, 064H, 05dH, 019H, 073H,
       DB  060H, 081H, 04fH, 0dcH, 022H, 02aH, 090H, 088H, 046H, 0eeH, 0b8H, 014H, 0deH, 05eH, 00bH, 0dbH,
       DB  0e0H, 032H, 03aH, 00aH, 049H, 006H, 024H, 05cH, 0c2H, 0d3H, 0acH, 062H, 091H, 095H, 0e4H, 079H,
       DB  0e7H, 0c8H, 037H, 06dH, 08dH, 0d5H, 04eH, 0a9H, 06cH, 056H, 0f4H, 0eaH, 065H, 07aH, 0aeH, 008H,
       DB  0baH, 078H, 025H, 02eH, 01cH, 0a6H, 0b4H, 0c6H, 0e8H, 0ddH, 074H, 01fH, 04bH, 0bdH, 08bH, 08aH,
       DB  070H, 03eH, 0b5H, 066H, 048H, 003H, 0f6H, 00eH, 061H, 035H, 057H, 0b9H, 086H, 0c1H, 01dH, 09eH,
       DB  0e1H, 0f8H, 098H, 011H, 069H, 0d9H, 08eH, 094H, 09bH, 01eH, 087H, 0e9H, 0ceH, 055H, 028H, 0dfH,
       DB  08cH, 0a1H, 089H, 00dH, 0bfH, 0e6H, 042H, 068H, 041H, 099H, 02dH, 00fH, 0b0H, 054H, 0bbH, 016H


RCON DB 01H,0H,0H,0H
    
                                         
INPUT DB 32h, 43h, 0f6h, 0a8h, 88h, 5ah, 30h, 8dh, 31h, 31h, 98h, 0a2h, 0e0h, 37h, 07h,34h
MIXCOLUMN_MX DB 02H , 01H , 01H , 03H , 03H , 02H , 01H , 01H , 01H, 03H , 02H , 01H , 01H , 01H , 03H , 02H
COUNT DB 10H
FOUR DW 04H  
OUTPUT DB 0d4H ,0bfH, 5dH, 30H, 0e0H, 0b4H, 52H, 0aeH, 0b8H , 41H, 11H, 0f1H, 1eH, 27H, 98H, 0e5H,"$"
CIPHERKEY DB 2bh ,7eh ,15h , 16h, 28h , 0aeh , 0d2h , 0a6h , 0abh , 0f7h , 15h , 88h , 09h ,0cfh , 4fh ,3ch
ROTWORD DB 09H, 0CFH, 4FH,3CH
TWO DB 2H
        
.CODE

MOV AX , @DATA
MOV DS, AX 
XOR AX,AX
XOR CX,CX   
          
          
CALL IN_MESSAGE 
CALL IN_KEY
          
MOV SI , 33H
MOV DL,SBOX [SI] 

CALL ADDROUNDKEY 
MOV CX, 09H  

LOOP_ENC:   

 PUSH CX
  CALL SUBBYTES
  CALL SHIFTROWS
  CALL MIXCOLUMNS    
  CALL TRANSFER
  CALL ADDROUNDKEY
 POP CX
LOOP LOOP_ENC  

CALL SUBBYTES
CALL SHIFTROWS
CALL ADDROUNDKEY
CALL TRANSFER2 
CALL OUT_ENC   
RET 
  
  
  
IN_MESSAGE PROC NEAR 
    
      
   MOV DX, OFFSET MESSAGE
   MOV AH, 9H
   INT 21h
   MOV SI,0H    
   MOV CX,10H 
   MOV BX,0H
   LOOP_13:
                
   MOV AX,0H
   MOV AH,01H
 ;  MOV AX, OFFSET INPUT
   INT 21H 
   MOV INPUT[BX][SI],AL  
   INC BX
                
   LOOP LOOP_13
    
RET
IN_MESSAGE ENDP 

IN_KEY PROC NEAR
      
          
   MOV DX, OFFSET MESSAGE2
   MOV AH, 9H
   INT 21h
   MOV SI,0H    
   MOV CX,10H 
   MOV BX,0H
   LOOP_14:
                
   MOV AX,0H
   MOV AH,01H
 ;  MOV AX, OFFSET INPUT
   INT 21H 
   MOV CIPHERKEY[BX][SI],AL  
   INC BX
                
   LOOP LOOP_14
   
      
RET
IN_KEY ENDP

OUT_ENC PROC NEAR 
    
   MOV DX, OFFSET MESSAGE3
   MOV AH, 9H
   INT 21h
   MOV SI,0H    
   MOV CX,1H 
   MOV BX,0H
   MOV DX , 0H
   LOOP_15:
                
   MOV AX,0H
   MOV AH,09H
   MOV DX,OFFSET OUTPUT[BX][SI]
   INT 21H 
     
   INC BX
                
   LOOP LOOP_15  
     
    
    
RET
OUT_ENC ENDP         
         
TRANSFER2 PROC NEAR 
    
    MOV CX,10H
    MOV BX,00H  
    MOV AX,00H 
    
    LOOP_12:
         
         MOV AL, INPUT[BX]
         MOV OUTPUT [BX],AL
         INC BX
         LOOP LOOP_12  
RET
TRANSFER2 ENDP 

                   
TRANSFER PROC NEAR 
    
    MOV CX,10H
    MOV BX,00H  
    MOV AX,00H 
    
    LOOP_4:
         
         MOV AL, OUTPUT[BX]
         MOV INPUT [BX],AL
         INC BX
         LOOP LOOP_4  
RET
TRANSFER ENDP
                
                
                
SUBBYTES PROC NEAR
  
  MOV CX,10H 
  MOV SI,0H 
  MOV BH,0H
  
  LOOP_5:      
         MOV BL, INPUT [SI]
         MOV AL, SBOX [BX] 
         MOV INPUT [SI] ,AL
         INC SI
         
  LOOP LOOP_5
          
         

   
RET
SUBBYTES ENDP 

SHIFTROWS PROC NEAR


 MOV AL, INPUT
 MOV OUTPUT,AL
  
 
 MOV AL , INPUT[5H]
 MOV OUTPUT[1],AL
 
 MOV AL, INPUT [0AH]
 MOV OUTPUT[2], AL  
 
 MOV AL, INPUT [0FH]
 MOV OUTPUT[3], AL 
 
 MOV AL, INPUT [04H]
 MOV OUTPUT[4], AL 
 
 MOV AL, INPUT [09H]
 MOV OUTPUT[5], AL 
 
 MOV AL, INPUT [0EH]
 MOV OUTPUT[6], AL
 
 MOV AL, INPUT [03H]
 MOV OUTPUT[7], AL
 
 MOV AL, INPUT [08H]
 MOV OUTPUT[8], AL
 
 MOV AL, INPUT [0DH]
 MOV OUTPUT[9], AL
 
 MOV AL, INPUT [02H]
 MOV OUTPUT[0AH], AL  
 
 MOV AL, INPUT [07H]
 MOV OUTPUT[0BH], AL     
 
 MOV AL, INPUT [0CH]
 MOV OUTPUT[0CH], AL
 
 MOV AL, INPUT [01H]
 MOV OUTPUT[0DH], AL 
 
 MOV AL, INPUT [06H]
 MOV OUTPUT[0EH], AL
 
 MOV AL, INPUT [0BH]
 MOV OUTPUT[0FH], AL
  
  
CALL TRANSFER   
    
RET
SHIFTROWS ENDP

                                   
MIXCOLUMNS PROC NEAR
    MOV AL,04H
    MOV COUNT, AL
    MOV AX ,04H
    MOV FOUR ,AX 
    
    MOV CL ,COUNT
    MOV CH ,00H
    MOV BX ,0H
    MOV SI ,0H  
    
    LOOP_1:       
          MOV COUNT,CL
          PUSH CX 
          MOV CX,4H
          PUSH BX
          PUSH SI 
        LOOP_3: 
         PUSH CX
         PUSH BX
         PUSH SI   
         MOV FOUR,CX
         MOV CX,4H 
        LOOP_2:  
              
          MOV AL , MIXCOLUMN_MX [BX]  
          MOV AH , INPUT [SI]
          CMP AL,3
          JNZ L1 
          MOV AL,AH
          SHL AH,1
          JNC Z
          XOR AH,1BH
          Z:XOR AL,AH 
          JMP L3
          L1: 
              CMP AL,2
              JNZ L2 
              SHL AH,1
              MOV AL,AH 
              JNC L3
              XOR AL,1BH 
              JMP L3
              
          L2: 
            MOV AL,AH
         L3:MOV AH,00H
            PUSH AX
            ADD BX,4H 
            ADD SI,1H  
            
          LOOP LOOP_2 
                    
          POP CX
          MOV AX,0000H
          XOR AX,CX
          POP CX
          XOR AX,CX
          POP CX
          XOR AX,CX
          POP CX
          XOR AX,CX
          
          POP SI
          POP BX
          POP CX
          
          MOV OUTPUT [BX][SI],AL
          
  
          MOV CX,FOUR
          INC BX
          
          LOOP LOOP_3 
          POP SI
          POP BX
          POP CX
          MOV BX,0H
          ADD SI,4H 
          MOV CL,COUNT 
          MOV CH,00H 
          CMP SI,10H  
          JZ LEND
     
    LOOP LOOP_1  
    
    LEND:
    

    
    RET
    MIXCOLUMNS ENDP  

ADDROUNDKEY PROC NEAR 
    CMP RCON, 0H
    JNZ LZ2 
    
    MOV RCON,1BH 
   
    
   LZ2: MOV CX, 10H 
    MOV BX,0H 
    
    LOOP_6:
        
        MOV AL,CIPHERKEY[BX]
        XOR INPUT[BX], AL
        INC BX
        
    LOOP LOOP_6
    
    ;KEY SCHEDULING
    MOV CX, 4H
    MOV BX, 0CH 
    MOV SI,0H
    
    LOOP_7:
         
         MOV AL, CIPHERKEY[BX]   
         MOV ROTWORD [SI], AL
         INC BX 
         INC SI
         
    LOOP LOOP_7
    
    MOV AL, ROTWORD
    MOV AH, ROTWORD [1H]
    MOV ROTWORD[1H],AL
    MOV ROTWORD, AH 
    
    MOV AL,ROTWORD[1H] 
    MOV AH,ROTWORD[2H]
    MOV ROTWORD[1H],AH
    MOV ROTWORD[2H],AL 
    
    MOV AL,ROTWORD[2H] 
    MOV AH,ROTWORD[3H]
    MOV ROTWORD[2H],AH
    MOV ROTWORD[3H],AL
    
    MOV CX,4H 
    MOV SI,0H 
    MOV BH,0H
      
    LOOP_8:      
           MOV BL, ROTWORD [SI]
           MOV AL, SBOX [BX] 
           MOV ROTWORD [SI] ,AL
           INC SI
             
    LOOP LOOP_8
    
    MOV CX,4H
    MOV BX,0H
    
    LOOP_9:
       MOV AL, ROTWORD[BX]
       XOR CIPHERKEY[BX],AL
       MOV AL, RCON[BX]    
       XOR CIPHERKEY[BX],AL 
       INC BX
    LOOP LOOP_9
    
    MOV AL,RCON      
    ADD RCON,AL
    CMP AL,0H
    JNZ LZ
    MOV RCON,1BH  
    
  LZ:  MOV BX,4H
    MOV CX,3H  
    MOV SI, 0H
    
    LOOP_10:   
    
        PUSH CX 
        MOV CX,4H
        LOOP_11:
          
          MOV AL,CIPHERKEY[SI]
          XOR CIPHERKEY[BX],AL
          INC BX 
          INC SI
          LOOP LOOP_11
      
        
        POP CX       
    LOOP LOOP_10
        
    
    RET
    ADDROUNDKEY ENDP






