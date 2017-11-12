import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.IOException;

/**
 * 
 * @author lichunmiao
 * 本程序用来把喂给biyacc的xml文件转换为喂给srcml的xml文件
 *
 */

public class ReverseProcessXML {
    
    public static void main(String[] args) {
        File file = new File(args[0]);
        
        String inputString = "";
        InputStreamReader reader = null;
        try {
            //System.out.println("以字符为单位读取文件内容，一次读一个字节：");
            // 一次读一个字符,真的是“一个”字符“一个”字符啊。。。
            reader = new InputStreamReader(new FileInputStream(file));
            int tempchar;
            while ((tempchar = reader.read()) != -1) {
                if (((char) tempchar) != '\r') {
                    inputString += (char) tempchar;
                }
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        //现在所有的字符都存在了inputString中，
        //下面对inputString进行处理,将inputString中的右尖括号和左尖括号之间的双引号去掉，除非本来就是字符串，
        //将处理后的结果存在outputString中
         
        String outputString = "";
       
        int start = 0;
        int rightBracketPos = inputString.indexOf(">",start);
        int nextLeftBracketPos = inputString.indexOf("<", rightBracketPos);
        String temp = "";
        
        String middleString = "";
    
        while(nextLeftBracketPos != -1)
        {
            /*if(inputString.substring(start, rightBracketPos+1).equals("<literal type=\"string\">"))
            {
                middleString = inputString.substring(rightBracketPos+3, nextLeftBracketPos-3) + "\""; 
            }
            else
            {*/
            
            temp = inputString.substring(rightBracketPos+1, nextLeftBracketPos);
            middleString = "";
            
            for(int i=0;i<temp.length();)
            {
                if(temp.charAt(i) == '\"') 
                   i++;
                else if(i+1 < temp.length() && temp.substring(i, i+2).equals("\\n"))
                {
                	middleString += "\\n";
                    i += 2;
                }
                else if(i+1 < temp.length() && temp.substring(i, i+2).equals("\\t"))
                {
                	middleString += "\\t";
                    i += 2;
                }
                else if (temp.charAt(i) == '\\')//后面的字符应该保留
                {
                    middleString += temp.substring(i+1, i+2);
                    i += 2;
                }
                else
                {
                    middleString += temp.substring(i, i+1);
                    i++;
                }
            }
            //}
            
            outputString += ( inputString.substring(start, rightBracketPos+1) 
                                  +  middleString);
                
            start = nextLeftBracketPos;
            rightBracketPos = inputString.indexOf(">", start);
            nextLeftBracketPos = inputString.indexOf("<", rightBracketPos);
        }
        
        outputString += inputString.substring(start, inputString.length());
      
        //下面将outputString写入新的xml文件中

        File file2 = new File(args[1]);
        
        if(!file2.exists())      
        {      
            try {      
                file2.createNewFile();      
            } catch (IOException e) {         
                e.printStackTrace();      
            }      
        } 
        try {  
            FileWriter fileWriter = new FileWriter(file2);  
            String s = new String(outputString);  
            fileWriter.write(s);  
            fileWriter.close(); // 关闭数据流  
  
        } catch (Exception e) {  
            e.printStackTrace();  
        } 
      }
}
