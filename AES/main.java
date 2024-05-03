import java.util.*;

public class App 
{
    public static void main(String[] args) throws Exception 
  {
        Scanner sc = new Scanner(System.in);

        String txt = sc.nextLine();     //텍스트 입력
        String key = sc.nextLine();     //키 입력

        AES x = new AES(txt, key);      //AES 알고리즘을 사용하기 위한 AES 객체 생성 및 입력 받은 텍스트와 키를 생성자를 통해 설정

        x.encrypt();            //암호화
        x.decrypt();            //복호화

        sc.close();
    }
}
