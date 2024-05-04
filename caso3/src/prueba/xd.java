package prueba;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class xd {
    public static void main(String[] args) {
        try {
            // Arreglo de bytes que representa la clave secreta
            byte[] keyBytes = "your_secret_key".getBytes();

            // Arreglo de bytes que representa el mensaje
            byte[] messageBytes = "your_message".getBytes();

            // HMAC esperado (deberías obtener esto de forma segura de alguna parte)
            String expectedHmacHex = "AQUI_EL_HMAC_ESPERADO_EN_HEXADECIMAL";
            byte[] expectedHmac = hexStringToByteArray(expectedHmacHex);

            // Crear una clave secreta usando la especificación HMAC SHA256
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "HmacSHA256");

            // Obtener una instancia de Mac para HMAC SHA256
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);

            // Procesar el arreglo de bytes del mensaje para obtener el MAC
            byte[] hmacBytes = mac.doFinal(messageBytes);

            // Verificar el HMAC
            if (Arrays.equals(hmacBytes, expectedHmac)) {
                System.out.println("HMAC verification passed!");
            } else {
                System.out.println("HMAC verification failed!");
            }

            // Mostrar el resultado como un String hexadecimal
            System.out.println("Generated HMAC-SHA256: " + bytesToHex(hmacBytes));

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    // Función auxiliar para convertir bytes a string hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    // Función auxiliar para convertir un string hexadecimal a un arreglo de bytes
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}

