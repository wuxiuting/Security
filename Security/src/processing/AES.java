package processing;

/**
*@author: Wu Xiuting
*/
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
public class AES {
	
  static String ALGORITHM = "AES";
  String setKey = "X";
  String symKey = "";

  public AES()   {
	  
  }
  
  public String getSymKey() throws NoSuchAlgorithmException {
	  if (setKey != "") {
		 symKey =  getKeyByPass(setKey);
	  }
	  else symKey = ranKey();
	  return symKey;	  
  }
  
  /**
  * 随机生成秘钥 
  */
  public static String encrypt(String plainText, String symKey) throws NoSuchAlgorithmException, NoSuchPaddingException, 
  InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	    //AES加密
		SecretKey secretKey2 = new SecretKeySpec(hexStringToBytes(symKey), ALGORITHM);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey2);
		byte[] cipherByte = cipher.doFinal(plainText.getBytes()); //加密
		String result = byteToHexString(cipherByte);
		return result;
  }
  
  public static String decrypt(String security, String symKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		//AES解密
		SecretKey secretKey3 = new SecretKeySpec(hexStringToBytes(symKey), ALGORITHM);//恢复密钥
		Cipher cipher2 = Cipher.getInstance(ALGORITHM);//Cipher完成加密或解密工作类
		cipher2.init(Cipher.DECRYPT_MODE, secretKey3);//对Cipher初始化，解密模式
		byte[] cipherByte2 = cipher2.doFinal(hexStringToBytes(security));//解密data
		return new String(cipherByte2);
  }
  
  public static String hexStringToString(String s) {
	    if (s == null || s.equals("")) {
	        return null;
	    }
	    s = s.replace(" ", "");
	    byte[] baKeyword = new byte[s.length() / 2];
	    for (int i = 0; i < baKeyword.length; i++) {
	        try {
	            baKeyword[i] = (byte) (0xff & Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16));
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }
	    try {
	        s = new String(baKeyword, "UTF-8");
	        new String();
	    } catch (Exception e1) {
	        e1.printStackTrace();
	    }
	    return s;
	}
  
  public static byte[] hexStringToBytes(String hexString) {   
	    if (hexString == null || hexString.equals("")) {   
	        return null;   
	    }   
	    hexString = hexString.toUpperCase();   
	    int length = hexString.length() / 2;   
	    char[] hexChars = hexString.toCharArray();   
	    byte[] d = new byte[length];   
	    for (int i = 0; i < length; i++) {   
	        int pos = i * 2;   
	        d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));   
	    }   
	    return d;   
	}
  
  private static byte charToByte(char c) {   

	    return (byte) "0123456789ABCDEF".indexOf(c);   

} 
  
public static String ranKey() throws NoSuchAlgorithmException {
    try {
      KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
      String key = "1234";
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
      random.setSeed(key.getBytes());
      kg.init(128,random);
      //要生成多少位，只需要修改这里即可128, 192或256
      SecretKey sk = kg.generateKey();
      byte[] b = sk.getEncoded();
      String s = byteToHexString(b);
      return s;
    }
    catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      System.out.println("没有此算法。");
      return null;
    }
    
  }
  /**
  * 使用指定的字符串生成秘钥
  */
  public static String getKeyByPass(String password) {
    //生成秘钥
    try {
      KeyGenerator kg = KeyGenerator.getInstance("AES");
      //生成128位的密钥
      kg.init(128, new SecureRandom(password.getBytes()));
      SecretKey sk = kg.generateKey();
      byte[] b = sk.getEncoded();
      String s = byteToHexString(b);
      return s;
    }
    catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      System.out.println("没有此算法。");
      return null;
    }
  }
  /**
  * byte数组转化为16进制字符串
  * @param bytes
  * @return
  */
  public static String byteToHexString(byte[] bytes) {
    StringBuffer sb = new StringBuffer();
    for (int i = 0; i < bytes.length; i++) {
      String strHex=Integer.toHexString(bytes[i]);
      if(strHex.length() > 3) {
        sb.append(strHex.substring(6));
      } else {
        if(strHex.length() < 2) {
          sb.append("0" + strHex);
        } else {
          sb.append(strHex);
        }
      }
    }
    return sb.toString();
  }
}
