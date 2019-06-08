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
public class DES {
	
  static String ALGORITHM = "DES";
  String setKey = "X";
  String symKey = "";
  static SecretKey secretKey2; 

  public DES()   {
	  
  }
  
  public SecretKey getSymKey() throws NoSuchAlgorithmException {
	  if (setKey != "") {
		 symKey =  getKeyByPass(setKey);
	  }
	  else symKey = ranKey();
	  secretKey2 = new SecretKeySpec(hexStringToBytes(symKey), ALGORITHM);
	  return secretKey2;	  
  }
  
 //随机生成秘钥
  public static String encrypt(String plainText, SecretKey secretKey2) throws NoSuchAlgorithmException, NoSuchPaddingException, 
  InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	    //DES加密
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey2);
		byte[] cipherByte = cipher.doFinal(plainText.getBytes()); //加密
		String result = byteToHexString(cipherByte);
		return result;
  }
  
  public static String decrypt(String security, SecretKey secretKey2) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		//DES解密
		Cipher cipher2 = Cipher.getInstance(ALGORITHM);//Cipher完成加密或解密工作类
		cipher2.init(Cipher.DECRYPT_MODE, secretKey2);//对Cipher初始化，解密模式
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
      hexString = hexString.toLowerCase();
      final byte[] byteArray = new byte[hexString.length() >> 1];
      int index = 0;
      for (int i = 0; i < hexString.length(); i++) {
          if (index  > hexString.length() - 1)
              return byteArray;
          byte highDit = (byte) (Character.digit(hexString.charAt(index), 16) & 0xFF);
          byte lowDit = (byte) (Character.digit(hexString.charAt(index + 1), 16) & 0xFF);
          byteArray[i] = (byte) (highDit << 4 | lowDit);
          index += 2;
      }
      return byteArray;
  }

public static String ranKey() throws NoSuchAlgorithmException {
    try {
      KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
      String key = "1234";
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
      random.setSeed(key.getBytes());
      kg.init(56,random);
      //要生成56位
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

//使用指定的字符串生成秘钥
  public static String getKeyByPass(String password) {
    //生成秘钥
    try {
      KeyGenerator kg = KeyGenerator.getInstance("DES");
      //根据输入生成56位的随机密钥
      kg.init(56, new SecureRandom(password.getBytes()));
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
