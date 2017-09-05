package com.bouygues.esav.test;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.bouygues.esav.mobile.ws.util.FileUtils;

public class RSAKeyTest {

	private static final String PRIVATE_KEY_FILE = "D:\\key\\private_key.der";

	private static final String ENCRYPTED_STRING = "le7HPsQRBBM5ZJsW5eg8hxNV545YqJBCzZnpdo4qmy0CrHoa1xSpwbRu4Xiud31n0CMJcojjZg4iyQ5WohnJ0vP1Jgja5x9nOmEPPdLZ1IaGnVfhNdOa4N/cGiWDaobzLZapM/alemnt7IFfXAYtZlKxmcWjnfvxzu/X9Z3NRyvZajwXUC4SteZOvRSPUb2b9tmlBp8Nk0+Dhnp6Zo5fYDbT3yp27VpVv/vU+0p3oKAuZHIbtYLMQRFcYbWj4gGBsmMY5Yg2lgaqyLciMokMRTFFuVfgIpyaQTHHAGW7t+XUFjPUMA97eYBUW/URYkaj7pCq1v7v7I0ggVNW3NLMLw==";

	public static void main(String[] args) {
//		System.out.println(decrypt(ENCRYPTED_STRING));
		int[] sortSearch = sortSearch(new int[]{65, 98, 98, 0, 0, 0, 2,1,1,1,3,3,4,5},  10);
		for( int i : sortSearch ) {
			System.out.println(i);
		}
		String xml =  "<?xml version = \"1.0\" ?>\n" + 
				 "<log>\n"
					+ "<entry id = \"1\">\n"
						+ "<message>abc</message>\n"
					+ "</entry>\n"
					+ "<entry id = \"2\">\n"
						+ "<message>xyz</message>\n"
					+ "</entry>\n"
				+ "</log>\n";
		try {
			String id = getIdsByMessage(xml, "xyz");
			System.out.println("id = " + id);
		}
		catch( Exception e ) {
			e.printStackTrace();
		}
	
	}
	
	private static int[] sortSearch(int[] a, int lessThan){
		int[] filter = new int[lessThan];
		int[] found = new int[lessThan];
		int resultSize = 0;
		for(int i = 0; i < a.length; i ++){
			if(a[i] < lessThan && found[a[i]] != 1){
				filter[resultSize] = a[i];
				found[a[i]] = 1;
				resultSize ++;
			}
		}
		int[] result = new int[resultSize];
		for(int i = 0; i <resultSize ; i ++){
			result[i] = filter[i];
		}
		sort(result);
		return result;
	}
	
	private static void sort(int[] a) {
		for (int i = 0; i < a.length; i++) 
        {
            for (int j = i + 1; j < a.length; j++) 
            {
                if (a[i] < a[j]) 
                {
                    int temp = a[i];
                    a[i] = a[j];
                    a[j] = temp;
                }
            }
        }
    }
	
	private static String getIdsByMessage(String xml, String message) throws ParserConfigurationException, SAXException, IOException{
		Document document = buildDom(xml);
		return getIdsByMessage(document, message);
	}
 
	private static String getIdsByMessage(Document document, String message){
		NodeList nodeList = document.getElementsByTagName("message");
		if(nodeList == null || nodeList.getLength() == 0){
			throw new IllegalStateException("Cannot find node with tag name message");
		}
		Node node = getNodeByValue(message, nodeList);
		if(node == null) {
			throw new IllegalStateException("Cannot find node with message "+ message);
		}
		Node parentNode = node.getParentNode();
		if(parentNode == null){
			throw new IllegalStateException("Cannot find id node of message "+ message);
		}
		NamedNodeMap attributes = parentNode.getAttributes();
		for(int i = 0; i< attributes.getLength(); i ++){
			Node item = attributes.item(i);
			if(item.getNodeName().equals("id")){
				return item.getNodeValue();
			}
		}
		return null;
	}
	
	private static Node getNodeByValue(String nodeValue, NodeList nodeList){
		for( int i = 0; i < nodeList.getLength(); i ++) {
			Node item = nodeList.item(i);
			item.getFirstChild().getNodeValue();
			if(item.getFirstChild().getNodeValue().equals(nodeValue)){
				return item;
			}
		}
		return null;
	}
	
   private static Document buildDom(String xml) throws ParserConfigurationException, SAXException, IOException{
	   DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
	   InputSource is = new InputSource();
	   is.setCharacterStream(new StringReader(xml));
	   Document document = documentBuilder.parse(is);
	   return document;
   }

	public static String decrypt(String ciphertext) {
		if( ciphertext.length() == 0 )
			return null;
		byte[] dec = Base64.decodeBase64(ENCRYPTED_STRING);
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			System.out.println("Private Key file name----");
			PrivateKey privateKey = readPrivateKeyFromFile(PRIVATE_KEY_FILE);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decrypted = cipher.doFinal(dec);
			return new String(decrypted, "UTF-8");
		}
		catch( Exception e ) {
			e.printStackTrace();
			return null;
		}
	}

	public static PrivateKey readPrivateKeyFromFile(String fileName) throws IOException, Exception {
		byte[] keyBytes = FileUtils.readBytes(fileName);

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}
}
