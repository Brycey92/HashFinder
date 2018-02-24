import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

/**
 * @author Bryce Browner
 *
 */
public class HashFinder {
	/**
	 * @param args args[0] is the file to search, args[1] is the hash to search for, args[2] is the length of the key, args[3] is the hashing algorithm
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {
		if(args.length < 2 || args.length > 4) {
			System.out.println("Usage: <file> <hash> [key length] [algorithm]");
			System.out.println("File path can be relative or absolute.");
			System.out.println("Hash must be specified in hex digits, and is case insensitive.");
			System.out.println("Key length is in bytes, must be positive and non-zero, and defaults to 16.");
			System.out.println("Possible algorithms: MD2, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512");
			System.out.println("Algorithm defaults to SHA-256.");
			return;
		}
		
		boolean failedFileExistsCheck = false;
		boolean failedFileIsNotDirCheck = false;
		boolean failedHashOddCheck = false;
		boolean failedHashLengthCheck = false;
		boolean failedKeyLengthParseCheck = false;
		boolean failedFileLengthCheck = false;
		boolean failedAlgorithmCheck = false;
		int keyLength = 16;
		String algorithm = "SHA-256";
		
		File file = new File(args[0]);
		
		//make sure the file exists
		if(!file.exists()) {
			System.out.println("File " + args[0] + " does not exist!");
			failedFileExistsCheck = true;
		}
		//make sure the file is not a directory
		else if(file.isDirectory()) {
			System.out.println("File " + args[0] + " is a directory!");
			failedFileIsNotDirCheck = true;
		}
		
		//make sure the hash has an even number of hex digits
		if(args[1].length() % 2 == 1) {
			System.out.println("Your given hash has an odd number of hex digits!");
			failedHashOddCheck = true;
		}
		
		if(args.length == 4) {
			//make sure the user selected one of the supported algorithms
			algorithm = args[3];
			if(!(	algorithm.equalsIgnoreCase("MD2") ||
					algorithm.equalsIgnoreCase("MD5") ||
					algorithm.equalsIgnoreCase("SHA-1") ||
					algorithm.equalsIgnoreCase("SHA-224") ||
					algorithm.equalsIgnoreCase("SHA-256") ||
					algorithm.equalsIgnoreCase("SHA-384") ||
					algorithm.equalsIgnoreCase("SHA-512"))) {
				failedAlgorithmCheck = true;
			}
		}
		
		//a byte array representation of the hash we were given to find
		byte[] origHash = null;
		
		if(!failedHashOddCheck && !failedAlgorithmCheck) {
			//make sure the length of the hash returned by the algorithm is the same as the length of the given hash
			MessageDigest testDigest;
			
			try {
				origHash = toByteArray(args[1]);
				
				testDigest = MessageDigest.getInstance(algorithm);
				byte[] hash = testDigest.digest(new byte[1]);
				if(hash.length != origHash.length) {
					System.out.println("Your hash is not the length returned by the " + algorithm + " algorithm!");
					System.out.println("Expected " + hash.length + " bytes, but your hash was " + origHash.length + " bytes!");
					failedHashLengthCheck = true;
				}
			} catch(NoSuchAlgorithmException e) {
				System.out.println(algorithm + " not recognized as an algorithm!");
				System.out.println("Possible algorithms: MD2, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512");
				failedHashLengthCheck = true;
			}
		}
		
		if(args.length >= 3) {
			//make sure the key length we're given can be parsed as an integer
			try {
				keyLength = Integer.parseInt(args[2]);
			} catch(NumberFormatException e) {
				System.out.println("Your key length could not be parsed as a positive integer!");
				failedKeyLengthParseCheck = true;
			}
			
			if(!failedKeyLengthParseCheck && keyLength <= 0) {
				System.out.println("Key length must be a positive non-zero integer!");
				failedKeyLengthParseCheck = true;
			}
		}
		
		//make sure the file is at least as long as the length of the key we're searching for
		if(!failedFileExistsCheck && !failedFileIsNotDirCheck && file.length() < keyLength) {
			System.out.println("File length is shorter than the key length!");
			failedFileLengthCheck = true;
		}
		
		//this prints here instead of with its check in order to keep the verification messages in the same order as the parameters 
		if(failedAlgorithmCheck) {
			System.out.println("The algorithm you specified was not recognized!");
			System.out.println("Possible algorithms: MD2, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512");
		}
		
		//if any of the verification checks failed, stop running
		if(		failedFileExistsCheck ||
				failedFileIsNotDirCheck ||
				failedHashOddCheck ||
				failedHashLengthCheck ||
				failedKeyLengthParseCheck ||
				failedFileLengthCheck ||
				failedAlgorithmCheck) {
			System.exit(1);
		}
		
		//----------READY TO BEGIN!----------
		
		FileInputStream in = new FileInputStream(file);
		byte[] buf = new byte[keyLength];
		
		in.read(buf);
		int curByte = -2;
		
		while(curByte != -1) {
			MessageDigest digest;
			
			try {
				digest = MessageDigest.getInstance(algorithm);
				byte[] hash = digest.digest(buf);
				if(Arrays.equals(hash, origHash)) {
					System.out.println("Hex string " + toHexString(buf) + " matches given hash!");
					return;
				}
			} catch(NoSuchAlgorithmException e) {
				System.out.println(algorithm + " not recognized as an algorithm!");
				System.out.println("Possible algorithms: MD2, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512");
				in.close();
				return;
			}
			
			curByte = in.read();
			
			if(curByte != -1) {
				//shift the bytes left by 1 and add the newly read byte to the right
				for(int i = 0; i < (buf.length - 1); i++) {
					buf[i] = buf[i + 1];
				}
				buf[buf.length - 1] = (byte) curByte;
			}
		}
		
		System.out.println("No strings matching the given hash were found in the file.");
		in.close();
	}
	
	public static String toHexString(byte[] bytes) {
		return DatatypeConverter.printHexBinary(bytes);
	}
	
	public static byte[] toByteArray(String str) {
		return DatatypeConverter.parseHexBinary(str);
	}

}
