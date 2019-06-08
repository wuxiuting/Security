package processing;

/**
 * @author: Wu Xiuting
 */
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.border.BevelBorder;
import javax.swing.border.EmptyBorder;

import org.apache.commons.codec.binary.Base64;

public class Main extends JFrame {

	private static final long serialVersionUID = 1L;
	private static JPanel contentPane;
	public static String symAlgs = "DES";
	public static String shaAlgs = "SHA-1";
	public static String keySelect = "generate";
	public static String symKey = "";
	public static String sk = "";
	static String aesKey;
	static String desKey;
	static SecretKey secretKey;
	
	public String publicKeyA="";
	public String publicKeyB="";
	public String privateKeyA="";
	public String privateKeyB="";
	static String setKey = "";
	public String symStr = "";
	
	static StringBuilder sendInfo;
	static StringBuilder receInfo;
	static String plainText;
	static String am;
	static String bm;
	
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Main frame = new Main();
					frame.setVisible(true);
					frame.setTitle("加解密通信系统");
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	
	//求散列值
	public String calSha(String hashInput) throws Exception {
		String hash = new String();
		if (shaAlgs == "SHA-1") {
		hash = SHA.shaHash(hashInput);
		}
		else hash = MD5.getMD5Hash(hashInput);
		return hash;
	}
	
	//得到A的公私钥对
	static Map<Integer, String> keyAMap = new HashMap<Integer, String>();  //用于封装随机产生的公钥与私钥
	public static void aKeyPair() throws NoSuchAlgorithmException {  
		// KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象  
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");  
		// 初始化密钥对生成器，密钥大小为96-1024位  
		keyPairGen.initialize(512,new SecureRandom());  
		// 生成一个密钥对，保存在keyPair中  
		KeyPair keyPair = keyPairGen.generateKeyPair();  
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();   // 得到私钥  
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  // 得到公钥  
		String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));  
		// 得到私钥字符串  
		String privateKeyString = new String(Base64.encodeBase64((privateKey.getEncoded())));  
		// 将公钥和私钥保存到Map
		keyAMap.put(0,publicKeyString);  //0表示私钥
		keyAMap.put(1,privateKeyString);  //1表示公钥
		
	}  
	
	//得到B的公私钥对
	static Map<Integer, String> keyBMap = new HashMap<Integer, String>();  //用于封装随机产生的公钥与私钥
	public static void bKeyPair() throws NoSuchAlgorithmException {  
		// KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象  
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");  
		// 初始化密钥对生成器，密钥大小为96-1024位  
		keyPairGen.initialize(512,new SecureRandom());  
		// 生成一个密钥对，保存在keyPair中  
		KeyPair keyPair = keyPairGen.generateKeyPair();  
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();   // 得到私钥  
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  // 得到公钥  
		String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));  
		// 得到私钥字符串  
		String privateKeyString = new String(Base64.encodeBase64((privateKey.getEncoded())));  
		// 将公钥和私钥保存到Map
		keyBMap.put(0,publicKeyString);  //0表示私钥	
		keyBMap.put(1,privateKeyString);  //1表示公钥			
	}  
	
	//用A的私钥加密明文的散列值
	public String prEncry(String prInput) throws Exception {
	    //私钥加密的字符串
		aKeyPair();
		String prOutput = RSA.encrypt(prInput,keyAMap.get(0));
		return prOutput;
	}
	
	 public String getSymKey() throws NoSuchAlgorithmException {
		  if (setKey != "") {
			 symKey =  DES.getKeyByPass(setKey);
		  }
		  else symKey = DES.ranKey();
		  return symKey;
	 }
	
	 public void initKey() throws NoSuchAlgorithmException {
		//首先生成两个公私钥对
		bKeyPair();
		aKeyPair();
		//首先生成一组对称秘钥
		sk = getSymKey();
			
	 }
	
	 
	public SecretKey getSecretKey(String sk) {
		  secretKey = new SecretKeySpec(DES.hexStringToBytes(sk), "DES");
		  return secretKey;	  
	  }
	
	//A:用对称密钥(ECB操作模式)加密明文和签名后的散列值
	public String sendMessage(String str1,String str2,SecretKey sk) throws Exception {
		String str = str1+str2;
		if (symAlgs == "DES") {
			String encry = DES.encrypt(str,secretKey);
			return encry;
		}
		else if (symAlgs == "AES") {
			if (setKey != "") {
				aesKey = AES.getKeyByPass(setKey);
			}
			else {
				aesKey = AES.ranKey();
			}
			String encry = AES.encrypt(str,aesKey);
			return encry;
		}
		return null;
	}
	
	//A： 用B的公钥加密对称密钥
	public String keyEncry(String str) throws Exception {
		bKeyPair();
		String eKey = RSA.encrypt(str,keyBMap.get(0));
		return eKey;
	}
	
	//B： 用B的公私钥解密对称密钥
	public String keyDecry(String str) throws Exception {
		String dKey = RSA.decrypt(str,keyBMap.get(1));
		return dKey;
	}
	
	//B:用对称密钥解密信息,得到明文M和数字签名后的散列值
	public String getMessage(String str,SecretKey secretKey3) throws Exception {
		if (symAlgs == "DES") {
			System.out.println("解密的DES密钥："+symKey);
			String decry = DES.decrypt(str,secretKey3);
			return decry;
		}
		else if (symAlgs == "AES") {
			String decry = AES.decrypt(str,aesKey);
			return decry;
		}
		return null;
	}
	
	public String receHash(String input) throws Exception {
		int lengthM = plainText.length();
		int lengthInput = input.length();
		String reHash = input.substring(lengthM,lengthInput);
		return reHash;
	}
	
	//用A的公钥对H（M）进行解密
	public String puDecry(String prInput) throws Exception {
	    //私钥加密的字符串
		String puOutput = RSA.decrypt(prInput,keyAMap.get(1));
		return puOutput;
	}
	
	//B:对接收到的明文计算其散列值
	public String mHash(String rInput) throws Exception {
		String rhash = new String();
		String reM = rInput.substring(0,plainText.length());
		if (shaAlgs == "SHA-1") {
		rhash = SHA.shaHash(reM);
		}
		else rhash = MD5.getMD5Hash(reM);
		return rhash;
	}
	
	//运行程序
	public void run(String plainText) throws Exception {
		am = "发送方A的私钥RKa：" + keyAMap.get(0)+ "\n";
		am = am + "发送方A的公钥UKa：" + keyAMap.get(1)+ "\n";
		am = am + "对称密钥K：" + symKey+ "\n";
		String hashEncry = calSha(plainText);
		am = am + "明文M的散列值H（M）：" + hashEncry+ "\n";
		String prOut = prEncry(hashEncry);
		am = am + "PKa加密后的H（M）：" + prOut+ "\n";
		SecretKey sKey = getSecretKey(sk);
		String eKey = keyEncry(sk);
		String dKey = keyDecry(eKey);
		String sendStr = sendMessage(plainText, prOut,sKey);
		am = am + "对称密钥K加密后的M和签名H（M）：" + sendStr+ "\n";
		am = am + "UKb加密后的对称密钥：" + eKey;
		System.out.println(am + "\n");
		
		bm = "发送方B的私钥RKb：" + keyBMap.get(0)+ "\n";
		bm = bm + "发送方B的公钥UKb：" + keyBMap.get(1)+ "\n";
		bm = bm + "RKb加密后的对称密钥K'：" + dKey+ "\n";
		String receStr = getMessage(sendStr,sKey);
		bm = bm + "对称密钥K'解密得出的M'：" + receStr.substring(0,plainText.length())+ "\n";
		String receHash = receHash(receStr);
		bm = bm + "对称密钥K'解密得出的签名H（M'）：" + receHash+ "\n";
		String puDecry = puDecry(receHash);
		bm = bm + "UKa解密得出的H（M'）：" + puDecry+ "\n";
		String reHash = mHash(receStr);
		bm = bm + "明文M'的散列值H（M''）：" + reHash+ "\n";
		if(reHash.equals(puDecry)) {
			bm = bm + "比较H（M'）和H（M''）：解密成功";
		}
		else bm = bm + "比较H（M'）和H（M''）：解密失败";
		System.out.println(bm + "\n");
	}

	/**
	 * Create the frame.
	 */
	public Main() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 1000, 810);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(null);
		setContentPane(contentPane);
		
		JPanel panel_1 = new JPanel();
		panel_1.setBounds(10, 5, 200, 590);
		panel_1.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		panel_1.setLayout(null);
		contentPane.add(panel_1);
		
		JLabel label = new JLabel("设置");
		label.setHorizontalAlignment(SwingConstants.CENTER);
		label.setFont(new Font("微软雅黑", Font.PLAIN, 30));
		label.setBounds(70, 5, 60, 40);
		panel_1.add(label);
		
		JLabel lblHash = new JLabel("Hash算法：");
		lblHash.setFont(new Font("微软雅黑", Font.PLAIN, 25));
		lblHash.setBounds(10, 53, 135, 34);
		panel_1.add(lblHash);
		
		ButtonGroup hashGroup = new ButtonGroup();
		JRadioButton shaButton = new JRadioButton("SHA",true);
		shaButton.setFont(new Font("Tahoma", Font.PLAIN, 25));
		shaButton.setBounds(10, 93, 79, 35);
		JRadioButton md5Button = new JRadioButton("MD5",false);
		md5Button.setFont(new Font("Tahoma", Font.PLAIN, 25));
		md5Button.setBounds(10, 130, 83, 35);
		hashGroup.add(shaButton);
		hashGroup.add(md5Button);
		panel_1.add(shaButton);
		panel_1.add(md5Button);
		
		//为sha增加响应
		shaButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				shaAlgs = "SHA-1";
			}
		});
		//为md5增加响应
		md5Button.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				shaAlgs = "MD5";
			}
		});
		
		JLabel lblNewLabel = new JLabel("对称加密算法：");
		lblNewLabel.setHorizontalAlignment(SwingConstants.LEFT);
		lblNewLabel.setFont(new Font("微软雅黑", Font.PLAIN, 25));
		lblNewLabel.setBounds(10, 180, 175, 34);
		panel_1.add(lblNewLabel);
		
		ButtonGroup symmetricGroup = new ButtonGroup();
		JRadioButton desButton = new JRadioButton("DES",true);
		desButton.setFont(new Font("Tahoma", Font.PLAIN, 25));
		desButton.setBounds(10, 220, 77, 35);
		JRadioButton aesButton = new JRadioButton("AES",false);
		aesButton.setFont(new Font("Tahoma", Font.PLAIN, 25));
		aesButton.setBounds(10, 257, 75, 35);
		symmetricGroup.add(desButton);
		symmetricGroup.add(aesButton);
		panel_1.add(desButton);
		panel_1.add(aesButton);
		
		//增加DES选择的响应事件
		desButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				 symAlgs = "DES";
			}
		});
		//增加AES选择的响应事件
		aesButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				symAlgs = "AES";
			}
		});

		JLabel keyGenLabel = new JLabel("对称密钥来源:");
		keyGenLabel.setHorizontalAlignment(SwingConstants.LEFT);
		keyGenLabel.setFont(new Font("微软雅黑", Font.PLAIN, 25));
		keyGenLabel.setBounds(10, 308, 156, 35);
		panel_1.add(keyGenLabel);
		
		ButtonGroup keyGenGroup = new ButtonGroup();
		JRadioButton autoGenButton = new JRadioButton("自动生成",true);
		autoGenButton.setFont(new Font("微软雅黑", Font.PLAIN, 22));
		autoGenButton.setBounds(10, 350, 121, 35);
		JRadioButton presetButton = new JRadioButton("文本框输入",true);
		presetButton.setFont(new Font("微软雅黑", Font.PLAIN, 22));
		presetButton.setBounds(10, 390, 143, 35);
		keyGenGroup.add(autoGenButton);
		keyGenGroup.add(presetButton);
		panel_1.add(autoGenButton);
		panel_1.add(presetButton);
		
		JTextArea textArea = new JTextArea(3,14);
		textArea.setBounds(10, 430, 183, 94);
		textArea.setFont(new Font("微软雅黑", Font.PLAIN, 22));
		textArea.setLineWrap(true);
		panel_1.add(textArea);
		//给文本框添加滚动窗格
		JScrollPane textScrollPane = new JScrollPane(textArea);
		textScrollPane.setBounds(10, 430, 183, 94);
		panel_1.add(textScrollPane);
		
		//先进行设置的说明
		JLabel sm = new JLabel("请首先进行");
		sm.setHorizontalAlignment(SwingConstants.LEFT);
		sm.setFont(new Font("微软雅黑", Font.PLAIN, 25));
		sm.setBounds(40, 620, 183, 35);
		contentPane.add(sm);
		JLabel sm2 = new JLabel("设置的选择");
		sm2.setHorizontalAlignment(SwingConstants.LEFT);
		sm2.setFont(new Font("微软雅黑", Font.PLAIN, 25));
		sm2.setBounds(40, 660, 183, 35);
		contentPane.add(sm2);

		//自动生成按钮响应
		autoGenButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				setKey = "";
				textArea.setText("");
				textArea.setEnabled(false);
			}
		});
		//输入按钮响应
		presetButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent arg0) {
				setKey = textArea.getText();
				textArea.setEnabled(true);
			}
		});
				
		
		JButton btnNewButton = new JButton("确定");
		btnNewButton.setFont(new Font("微软雅黑", Font.PLAIN, 22));
		btnNewButton.setBounds(10, 540, 78, 39);
		panel_1.add(btnNewButton);
		
		JButton changeButton = new JButton("修改");
		changeButton.setFont(new Font("微软雅黑", Font.PLAIN, 22));
		changeButton.setBounds(115, 540, 78, 39);
		panel_1.add(changeButton);
		
		//输入明文显示
		JLabel lblNewLabel_1 = new JLabel("请输入明文：");
		lblNewLabel_1.setFont(new Font("微软雅黑", Font.PLAIN, 25));
		lblNewLabel_1.setBounds(240, 15, 150, 30);
		contentPane.add(lblNewLabel_1);
		
		JTextArea mTextArea = new JTextArea();
		mTextArea.setBounds(390, 13, 550, 40);
		mTextArea.setFont(new Font("微软雅黑", Font.PLAIN, 20));
		mTextArea.setLineWrap(true);
		JScrollPane mScrollPane = new JScrollPane(mTextArea);
		mScrollPane.setBounds(390, 13, 550, 40);
		contentPane.add(mScrollPane);
		
		//发送方显示框架
		JPanel panel = new JPanel();
		panel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		panel.setBounds(223, 120, 750, 290);
		contentPane.add(panel);
		panel.setLayout(null);
		
		JLabel lblNewLabel_2 = new JLabel("\u53D1\u9001\u65B9");
		lblNewLabel_2.setFont(new Font("微软雅黑", Font.PLAIN, 25));
		lblNewLabel_2.setBounds(325, 8, 81, 35);
		panel.add(lblNewLabel_2);
		
		JTextArea textArea_send = new JTextArea();
		textArea_send.setBounds(8, 46, 735, 250);
		textArea_send.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textArea_send.setFont(new Font("微软雅黑", Font.PLAIN, 20));
		textArea_send.setLineWrap(true);
		textArea_send.setEnabled(false);
		panel.add(textArea_send);
		JScrollPane sendScrollPane = new JScrollPane(textArea_send);
		sendScrollPane.setBounds(8, 46, 735, 250);
		panel.add(sendScrollPane);
		
		//接收方显示框架
		JPanel rPanel = new JPanel();
		rPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		rPanel.setBounds(223, 443, 750, 290);
		contentPane.add(rPanel);
		rPanel.setLayout(null);
		
		JLabel lblNewLabel_r = new JLabel("\u63A5\u6536\u65B9");
		lblNewLabel_r.setFont(new Font("微软雅黑", Font.PLAIN, 25));
		lblNewLabel_r.setBounds(325, 8, 81, 35);
		rPanel.add(lblNewLabel_r);
		
		JTextArea textArea_r = new JTextArea();
		textArea_r.setBounds(8, 46, 735, 250);
		textArea_r.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textArea_r.setFont(new Font("微软雅黑", Font.PLAIN, 20));
		textArea_r.setLineWrap(true);
		textArea_r.setEnabled(false);
		rPanel.add(textArea_r);
		JScrollPane rScrollPane = new JScrollPane(textArea_r);
		rScrollPane.setBounds(8, 46, 735, 250);
		rPanel.add(rScrollPane);
		
		//输入明文后的开始传送按钮
		JButton btnNewButton_1 = new JButton("\u5F00\u59CB\u4F20\u9001");
		btnNewButton_1.setFont(new Font("微软雅黑", Font.PLAIN, 22));
		btnNewButton_1.setBounds(750, 70, 123, 35);
		contentPane.add(btnNewButton_1);

	//设置面板的确定按钮事件处理
	btnNewButton.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent arg0) {
			//TODO 检查是否有秘钥输入，如果没有要提示
			desButton.setEnabled(false);
			aesButton.setEnabled(false);
			shaButton.setEnabled(false);
			md5Button.setEnabled(false);
			autoGenButton.setEnabled(false);
			presetButton.setEnabled(false);
			textArea.setEnabled(false);
			btnNewButton.setEnabled(false);
			try {
				initKey();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			btnNewButton_1.setEnabled(true);
			mTextArea.setEnabled(true);
		}
	});

	changeButton.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent arg0) {
			desButton.setEnabled(true);
			aesButton.setEnabled(true);
			shaButton.setEnabled(true);
			md5Button.setEnabled(true);
			autoGenButton.setEnabled(true);
			presetButton.setEnabled(true);
			if (!textArea.isEnabled())
			{
				textArea.setEnabled(true);
			}
			btnNewButton.setEnabled(true);
			mTextArea.setEnabled(false);
			btnNewButton_1.setEnabled(false);
			//清空加密数据
			mTextArea.setText("");
			//清空发送区域
			textArea_send.setText("");
			//清空接收区域
			textArea_r.setText("");
			changeButton.setEnabled(false);
		}
	});
	
	//开始传送按钮事件处理
	btnNewButton_1.addActionListener(new ActionListener() {
		@Override
		public void actionPerformed(ActionEvent arg0) {
			// TODO 检查是否有数据输入，如果没有要提醒
			plainText = mTextArea.getText();
			try {
				run(plainText);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			textArea_send.append(am);
			textArea_r.append(bm);
			changeButton.setEnabled(true);
		}
	});
}

}
