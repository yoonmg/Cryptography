public class AES {

    //외부로부터의 접근을 차단하기 위한 private 접근 지정자 사용
    private String[][] txt = new String[4][4];
    private String[][] key = new String[4][4];
    private String t;
    private String k;
    private String[][][] savedRoundKey = new String[10][4][4]; //복호화 할 떄 사용 할 라운드 키 저장 배열

    public static final String[][] S_Box = 
    {
        {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},
        {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},
        {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},
        {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
        {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
        {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
        {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
        {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
        {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
        {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
        {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
        {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
        {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
        {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
        {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
        {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}
    };

    public static final String[][] Inv_S_Box = 
    {
        {"52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB"},
        {"7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB"},
        {"54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E"},
        {"08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25"},
        {"72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92"},
        {"6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84"},
        {"90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06"},
        {"D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B"},
        {"3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73"},
        {"96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E"},
        {"47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B"},
        {"FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4"},
        {"1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F"},
        {"60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF"},
        {"A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61"},
        {"17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D"}
    };

    public static final int[] R_Constant = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};


    public static final int[][] Inv_Mix_Constant = 
    {
        {0x0e, 0x0b, 0x0d, 9},
        {9, 0x0e, 0x0b, 0x0d},
        {0x0d, 9, 0x0e, 0x0b},
        {0x0b, 0x0d, 9, 0x0e}
    };

    public static final int[][] Mix_Constant =
    {
        {02, 03, 01, 01},
        {01, 02, 03, 01},
        {01, 01, 02, 03},
        {03, 01, 01, 02}
    };

    public AES(String txt, String key)  //AES 클래스의 생성자
    {
        t = txt;
        k = key;
    }

    public void setInitialToHex()   //초기 텍스트 및 키를 16진수화 한 후 2차원 배열에 삽입
    {
        int index1 = 0;
        int index2 = 0;

        for(int i=0;i<4;i++) 
        {
            for(int j=0;j<4;j++) 
            {
                this.txt[j][i] = Integer.toHexString((int) t.charAt(index1++)).toUpperCase();
            }
        }
        
        /* toUpperCase()를 이용해 대문자로 바꿔주는 이유는 16진수가 소문자로 표시되기 때문에 문자열로 바꿀 때 대문자로
        바꿔줌으로써 S Box를 사용할 수 있게 하기 위해 사용 */

        for(int i=0;i<4;i++) 
        {
            for(int j=0;j<4;j++) {
                this.key[j][i] = Integer.toHexString((int) k.charAt(index2++)).toUpperCase();
            }
        }
    }

    public char[] setHexToInitial()
    {
        char[] arr = new char[16];
        int index = 0;

        for(int i=0;i<4;i++)
        {
            for(int j=0;j<4;j++)
            {
                int x = Integer.parseInt(this.txt[j][i], 16);
                char c = (char) x;
                arr[index++] = c;
            }
        }

        return arr;
    }

    //라운드 키 만들기
    public void GenerateRoundKey(String[][] roundKey, int round) 
    {
        //3번째 열 복사
        String[] w3 = new String[4];
        for(int i = 0; i < 4; i++) {

            w3[i] = this.key[i][3];
        }
    
        //왼쪽 쉬프트 연산 수행. 2차원 배열로 보면 위로 쉬프트
        String temp = w3[0];
        for(int i = 0; i < 3; i++) 
        {
            w3[i] = w3[i + 1];
        }
        w3[3] = temp;
    
        //S-Box 연산
        for(int i = 0; i < 4; i++) 
        {
            String row = String.valueOf(w3[i].charAt(0));
            String col = String.valueOf(w3[i].charAt(1));
            int r = Integer.parseInt(row, 16);
            int c = Integer.parseInt(col, 16);
            w3[i] = S_Box[r][c];
        }
    
        //라운드 상수를 이용해 XOR연산 수행
        w3[0] = String.format("%02X", Integer.parseInt(w3[0], 16) ^ R_Constant[round]);
        
        //새 라운드 키를 만들기 위한 XOR 연산
        String[][] newRoundKey = new String[4][4];
        for(int i = 0; i < 4; i++) 
        {
            newRoundKey[i][0] = String.format("%02X", Integer.parseInt(w3[i], 16) ^ Integer.parseInt(roundKey[i][0], 16));
        }
    
        for(int i = 0; i < 4; i++) 
        {
            newRoundKey[i][1] = String.format("%02X", Integer.parseInt(newRoundKey[i][0], 16) ^ Integer.parseInt(roundKey[i][1], 16));
        }
    
        for(int i = 0; i < 4; i++) 
        {
            newRoundKey[i][2] = String.format("%02X", Integer.parseInt(newRoundKey[i][1], 16) ^ Integer.parseInt(roundKey[i][2], 16));
        }
    
        for(int i = 0; i < 4; i++) 
        {
            newRoundKey[i][3] = String.format("%02X", Integer.parseInt(newRoundKey[i][2], 16) ^ Integer.parseInt(roundKey[i][3], 16));
        }
        
        this.key = newRoundKey;
    }

    //라운드 키 저장
    public void saveRoundKey(int round)
    {
        savedRoundKey[round] = this.key;
    }

    //저장된 라운드 키 꺼내기
    public void getRoundKey(int round)
    {
        this.key = savedRoundKey[round];
    }

    public void addRoundKey() 
    {
        for(int i=0;i<4;i++)
        {
            for(int j=0;j<4;j++)
            {
                this.txt[j][i] = String.format("%02X", Integer.parseInt(this.txt[j][i], 16) ^ Integer.parseInt(key[j][i],16));
            }
        }
    }

    public void sBytes()
    {
        for(int i=0;i<4;i++)
        {
            for(int j=0;j<4;j++)
            {
                String row = String.valueOf(this.txt[j][i].charAt(0));      //텍스트에 있는 String형 원소를 두개의 char형으로 나눈 후 S-Box의 행과 열에 맞추어 원소 가져오기
                String col = String.valueOf(this.txt[j][i].charAt(1));

                int r = Integer.parseInt(row, 16);
                int c = Integer.parseInt(col, 16);

                this.txt[j][i] = S_Box[r][c];
            }
        }
    }

    public void invSBytes()
    {
        for(int i=0;i<4;i++)
        {
            for(int j=0;j<4;j++)
            {
                String row = String.valueOf(this.txt[j][i].charAt(0));      //sBytes 연산의 역 연산
                String col = String.valueOf(this.txt[j][i].charAt(1));

                int r = Integer.parseInt(row, 16);
                int c = Integer.parseInt(col, 16);

                this.txt[j][i] = Inv_S_Box[r][c];
            }
        }
    }

    public void shiftRow()
    {
        String a = this.txt[1][0];
            
        for(int i=0;i<3;i++)
        {

            this.txt[1][i] = this.txt[1][i+1];      //state의 1열 왼쪽으로 한칸 쉬프트
        }

        this.txt[1][3] = a;

        String b = this.txt[2][0];
        this.txt[2][0] = this.txt[2][2];
        this.txt[2][2] = b;

        String c = this.txt[2][1];          //state의 2열 왼쪽으로 두칸 쉬프트 == 인덱스 0,2와 1,3자리 바꿈
        this.txt[2][1] = this.txt[2][3];
        this.txt[2][3] = c;

        String d = this.txt[3][3];
        
        for(int i=3;i>0;i--)
        {
            this.txt[3][i] = this.txt[3][i-1];      //state의 3열을 왼쪽으로 세칸 쉬프트 == 오른쪽으로 한칸 쉬프트
        }

        this.txt[3][0] = d;
    }

    public void invShiftRow()
    {
        String a = this.txt[1][3];

        for(int i=2;i>=0;i--)
        {
            this.txt[1][i+1] = this.txt[1][i];      //state의 1열 오른쪽으로 한칸 쉬프트
        }

        this.txt[1][0] = a;

        String b = this.txt[2][0];
        this.txt[2][0] = this.txt[2][2];
        this.txt[2][2] = b;

        String c = this.txt[2][1];          //state의 2열 오른쪽으로 두칸 쉬프트 == 인덱스 0,2와 1,3자리 바꿈
        this.txt[2][1] = this.txt[2][3];
        this.txt[2][3] = c;

        String d = this.txt[3][0];
            
        for(int i=0;i<3;i++)
        {

            this.txt[3][i] = this.txt[3][i+1];      //state의 3열 오른쪽으로 3칸 쉬프트 == 왼쪽으로 한칸 쉬프트
        }

        this.txt[3][3] = d;
    }

    public void mixCol()
    {
        String[][] result = new String[4][4];

        int[][] a = new int[4][4];

        for (int i=0;i<4;i++) 
        {
            a[i] = multiply(i);     //행렬 곱 연산의 결과를 가져오기
        }

        for (int i=0;i<4;i++) 
        {
            for (int j=0;j<4;j++) 
            {
                result[i][j] = String.format("%02X", a[i][j]);  //결과 값에 삽입
            }
        }

        this.txt = result;
    }

    public void invMixCol()
    {
        String[][] result = new String[4][4];

        int[][] a = new int[4][4];

        for (int i=0;i<4;i++) 
        {
            a[i] = invMultiply(i);
        }

        for (int i=0;i<4;i++) 
        {
            for (int j=0;j<4;j++) 
            {
                result[i][j] = String.format("%02X", a[i][j]);
            }
        }

        this.txt = result;
    }

    //Mix Columns를 하기 위한 행렬 계산
    public int[] multiply(int a)
    {   
        int[] result = new int[4];
        int val = 0;

        for(int j=0;j<4;j++)
        {
            val = 0;
            for(int k=0;k<4;k++)
            {
                int x = Mix_Constant[a][k];
                int y = Integer.parseInt(this.txt[k][j], 16);

                if(x == 02)
                {   
                    /*최상위 비트가 1일 때 쉬프트 연산을 하면 오버플로우가 일어나기에
                     * 문제를 해결하기 위해 0x80(1000 0000)과 and 연산을 수행했을 때, 
                     * 0이 나오지 않으면 0x1B를 XOR 연산 해준다.
                     */
                    y = (y << 1) ^ ((y & 0x80) != 0 ? 0x1B : 0);
                }
                else if(x == 03)
                {
                    y = ((y << 1) ^ y)  ^ ((y &  0x80) != 0 ? 0x1B : 0);
                }

                y &= 0xFF;  //최대 8비트로 고정
                val ^= y;
            }

            result[j] = val;
        }

        return result;
    }

    public int[] invMultiply(int a)
    {
        int[] result = new int[4];
        int val = 0;

        for(int j=0;j<4;j++)
        {
            val = 0;
            for(int k=0;k<4;k++)
            {
                int x = Inv_Mix_Constant[a][k];
                int y = Integer.parseInt(this.txt[k][j], 16);

                //invMixColumns는 상수가 다르기 때문에 연산도 다르게 처리

                //x가 9일 때는 (((x * 2) * 2) * 2) + x와 같다
                if(x == 9)
                {   
                    /*최상위 비트가 1일 때 쉬프트 연산을 하면 오버플로우가 일어나기에
                     * 문제를 해결하기 위해 0x80(1000 0000)과 and 연산을 수행했을 때, 
                     * 0이 나오지 않으면 0x1B를 XOR 연산 해준다.
                     */

                    int tmp = y;
                    for(int i=0;i<3;i++)
                    {
                        if((y & 0x80) != 0)
                        {
                            y = (y << 1) ^ 0x1b;
                        }
                        else
                        {
                            y = y << 1;
                        }
                    }

                    y ^= tmp;
                }
                //x가 11, 즉 0x0b일 때는 ((((x * 2) * 2) + x) * 2) + x와 같다
                else if(x == 0x0b)
                {
                    int tmp = y;
                    for(int i=0;i<2;i++)
                    {
                        if((y & 0x80) != 0)
                        {
                            y = (y << 1) ^ 0x1b;
                        }
                        else
                        {
                            y = y << 1;
                        }
                    }

                    y ^= tmp;

                    if((y & 0x80) != 0)
                    {
                        y = (y << 1) ^ 0x1b;
                    }
                    else
                    {
                        y = y << 1;
                    }

                    y ^= tmp;
                }
                //x가 13, 즉 0x0d일 때는 ((((x * 2) + x) * 2) * 2) + x와 같다
                else if(x == 0x0d)
                {
                    int tmp = y;
                    if((y & 0x80) != 0)
                    {
                        y = (y << 1) ^ 0x1b;
                    }
                    else
                    {
                        y = y << 1;
                    }

                    y ^= tmp;

                    for(int i=0;i<2;i++)
                    {
                        if((y & 0x80) != 0)
                        {
                            y = (y << 1) ^ 0x1b;
                        }
                        else
                        {
                            y = y << 1;
                        }
                    }

                    y ^= tmp;
                }
                //x가 14, 즉 0x0e일 때는 ((((x * 2) + x) * 2) + x) * 2와 같다
                else if(x == 0x0e)
                {
                    int tmp = y;
                    if((y & 0x80) != 0)
                    {
                        y = (y << 1) ^ 0x1b;
                    }
                    else
                    {
                        y = y << 1;
                    }

                    y ^= tmp;

                    if((y & 0x80) != 0)
                    {
                        y = (y << 1) ^ 0x1b;
                    }
                    else
                    {
                        y = y << 1;
                    }

                    y ^= tmp;

                    if((y & 0x80) != 0)
                    {
                        y = (y << 1) ^ 0x1b;
                    }
                    else
                    {
                        y = y << 1;
                    }

                }

                y &= 0xFF;  //최대 8비트로 고정
                val ^= y;
            }

            result[j] = val;
        }

        return result;
    }

    //결과 확인
    public void encrypt()
    {   
        setInitialToHex();  //입력한 텍스트 및 키 16진수화
        addRoundKey();
        saveRoundKey(0);        //복호화 할 때 사용하기 위한 라운드키 저장

        //1 ~ 9라운드 
        for(int i=0;i<9;i++)
        {
            sBytes();
            shiftRow();
            mixCol();
            GenerateRoundKey(this.key, i);
            addRoundKey();
            saveRoundKey(i+1);
        }

        //마지막 라운드는 Mix Columns 없음
        sBytes();
        shiftRow();
        GenerateRoundKey(this.key, 9);
        addRoundKey();

        //이하는 출력 형식
        System.out.println("Encrypted message is: ");
        for(String[] x : this.txt)
        {
            for(String y : x)
            {
                System.out.print(y+" ");
            }
            System.out.println();
        }
        System.out.println();

        for(int i=0;i<4;i++)
        {
            for(int j=0;j<4;j++)
            {
                System.out.print(this.txt[j][i] + " ");
            }
        }

        System.out.println();
    }

    public void decrypt()
    {
        addRoundKey();

        //암호화의 반대 순서
        for(int i=9;i>0;i--)
        {
            invShiftRow();
            invSBytes();
            getRoundKey(i);      //암호화 할 때 저장한 라운드 키 꺼내 쓰기
            addRoundKey();
            invMixCol();
        }
        
        invShiftRow();
        invSBytes();
        getRoundKey(0);
        addRoundKey();

        //이하는 출력 형식
        System.out.println();
        System.out.println("Decrypted message is: ");
        for(String[] x : this.txt)
        {
            for(String y : x)
            {
                System.out.print(y+" ");
            }
            System.out.println();
        }

        System.out.println();

        for(int i=0;i<4;i++)
        {
            for(int j=0;j<4;j++)
            {
                System.out.print(this.txt[j][i] + " ");
            }
        }

        System.out.println();
        System.out.println();
        
        char[] ch = setHexToInitial();      //복호화 된 16진수 2차원 행렬을 평문으로 한번 더 변경

        System.out.println("So the result of 2D hex matirx is:");
        for(char x : ch)
        {
            System.out.print(x);
        }
    }
}
