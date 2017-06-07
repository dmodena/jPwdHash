/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jpwdhash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Classe para geração e validação de senha criptografada.
 * @author Micronos
 */
public  class JPwdHash {

    /**
     * Gera salt de String com valor aleatório.
     * @return salt
     */
    public static String gerarSalt() {
        // Gera 32 bytes de valores aleatórios        
        return toHexString(new SecureRandom().generateSeed(32));
    }
    
    /**
     * Gera senha criptografada a partir de salt e senha pura.
     * @param salt String com salt
     * @param senha String contendo senha em texto puro
     * @return senha criptografada
     */
    public static String gerarSenhaHash(String salt, String senha) {
        // Unindo salt e senha
        String saltAndPwd = new StringBuilder()
                .append(salt)
                .append(senha)
                .toString();
        
        String senhaHash = null;
        
        try {
            // Gera hash do conjunto de salt e senha usando SHA-256
            senhaHash = toHexString(MessageDigest.getInstance("SHA-256")
                    .digest(saltAndPwd.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(JPwdHash.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return senhaHash;
    }
    
    /**
     * Verifica senha contra senha criptografada.
     * @param salt String com salt
     * @param senha String contendo senha em texto puro
     * @param senhaHash Senha criptografada
     * @return true para senha válida, false caso contrário
     */
    public static boolean validarSenhaHash(String salt, String senha, String senhaHash) {
        // Gerando hash de salt e senha recebidos
        String senhaHashGerado = gerarSenhaHash(salt, senha);
        
        // Verificando se hash gerado é igual a hash recebido
        return senhaHashGerado.equals(senhaHash);
    }
    
    /**
     * Verifica senha contra senha criptografada, adicionando delay para evitar
     *  ataques repetitivos.
     * @param salt String com salt
     * @param senha String contendo senha em texto puro
     * @param senhaHash Senha criptografada
     * @param delay Delay em milisegundos
     * @return true para senha válida, false caso contrário
     */
    public static boolean validarSenhaHash(String salt, String senha, String senhaHash, long delay) {
        // Verificando validade de senha
        boolean valido = validarSenhaHash(salt, senha, senhaHash);
        
        try {
            // Aguardando tempo de delay
            Thread.sleep(delay);
        } catch (InterruptedException ex) {
            Logger.getLogger(JPwdHash.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return valido;
    }
    
    /**
     * Transforma array de bytes em String hexadecimal.
     * @param byteArray Array de bytes
     * @return String hexadecimal
     */
    private static String toHexString(byte[] byteArray) {
        StringBuilder stb = new StringBuilder();

        // Transforma cada byte em inteiro hexadecimal
        for (int i = 0; i < byteArray.length; i++) {
            stb.append(Integer.toHexString(0xff & byteArray[i]));
        }
        
        return stb.toString();
    }
}
