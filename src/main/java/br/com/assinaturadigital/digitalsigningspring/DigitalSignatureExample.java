/*
 * Copyright (C) 2024 Your Name
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package br.com.assinaturadigital.digitalsigningspring;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.itextpdf.io.font.constants.StandardFonts;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfPage;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.layout.Document;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;

import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

//Anotação para o Spring gerenciar esta classe como um bean
@Component
public class DigitalSignatureExample {

	private static final Logger logger = LoggerFactory.getLogger(DigitalSignatureExample.class);
    public static final String DEST = "uploads/tmp/";
    public static final String[] RESULT_FILES = new String[]{"assinado.pdf"};
    
    // Método para calcular o hash SHA-256 do arquivo original
    public static String calculateFileHash(String filePath) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(filePath)) {
            byte[] byteArray = new byte[1024];
            int bytesCount;
            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }
        }
        byte[] hashBytes = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Método para adicionar o rodapé com o hash e a mensagem em todas as páginas
    public static void addFooter(String pdfFilePath, String outputFilePath, String fileHash) throws IOException {
        PdfDocument pdfDoc = null;
        Document document = null;

        try {
            pdfDoc = new PdfDocument(new PdfReader(pdfFilePath), new PdfWriter(outputFilePath));
            document = new Document(pdfDoc);

            // Criar a fonte manualmente
            PdfFont font = PdfFontFactory.createFont(StandardFonts.HELVETICA);

            // Mensagem a ser adicionada
            String footerMessage = "Documento assinado eletronicamente, conforme MP 2.200-2/2001 e Lei 14.063/2020.";

            for (int i = 1; i <= pdfDoc.getNumberOfPages(); i++) {
                PdfPage page = pdfDoc.getPage(i);
                Rectangle pageSize = page.getPageSize();  // Obter as dimensões da página

                // Criar o texto a ser adicionado no rodapé
                String footerText = fileHash + " - " + footerMessage;

                // Usar PdfCanvas para desenhar o texto diretamente na página
                PdfCanvas pdfCanvas = new PdfCanvas(page);

                // Definir cor e fonte do texto
                pdfCanvas.beginText()
                        .setFontAndSize(font, 6)  // Usando a fonte Helvetica com tamanho 6
                        .setColor(ColorConstants.BLACK, true)
                        .moveText(pageSize.getWidth() / 2 - 200, 30)  // Centralizado horizontalmente, 30 unidades acima do rodapé
                        .showText(footerText)
                        .endText();

                pdfCanvas.release();
            }
        } finally {
            // Certificar-se de que os recursos são fechados
            if (document != null) {
                document.close();
            }
            if (pdfDoc != null) {
                pdfDoc.close();
            }
        }
    }

    public String signDocument(String keystorePath, String password, String pdfFilePath) throws GeneralSecurityException, IOException {
        logger.info("Iniciando processo de assinatura...");
        logger.info("Keystore path: {}", keystorePath);
        logger.info("Caminho do arquivo PDF: {}", pdfFilePath);

        // Adicionar o BouncyCastle provider
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        // Converter a senha em char array
        char[] passwordCharArray = password.toCharArray();

        // Criar o diretório de destino se não existir
        File file = new File(DEST);
        if (!file.exists() && !file.mkdirs()) {
            logger.error("Não foi possível criar o diretório de destino: {}", DEST);
            throw new IOException("Não foi possível criar o diretório de destino.");
        }

        // Carregar o KeyStore usando o caminho e senha fornecidos
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(fis, passwordCharArray);
            String alias = ks.aliases().nextElement();

            if (alias == null || !ks.isKeyEntry(alias)) {
                logger.error("Nenhum alias válido encontrado no KeyStore.");
                throw new GeneralSecurityException("Nenhum alias válido encontrado no KeyStore.");
            }

            PrivateKey pk = (PrivateKey) ks.getKey(alias, passwordCharArray);
            Certificate[] chain = ks.getCertificateChain(alias);

            if (chain == null) {
                logger.error("Cadeia de certificados não encontrada.");
                throw new GeneralSecurityException("Cadeia de certificados não encontrada.");
            }

            // Definir o caminho para o arquivo de saída (assinado.pdf)
            String outputFile = DEST + "assinado.pdf";

            // Calcular o hash do arquivo original
            logger.info("Calculando o hash do arquivo...");
            String fileHash = calculateFileHash(pdfFilePath);
            logger.info("Hash do arquivo original: {}", fileHash);

            // Adicionar o rodapé com o hash e a mensagem antes da assinatura
            logger.info("Adicionando rodapé ao arquivo PDF...");
            String pdfWithFooter = DEST + "temp_with_footer.pdf"; // Arquivo temporário com o rodapé adicionado
            addFooter(pdfFilePath, pdfWithFooter, fileHash); // Modifica o PDF com o rodapé

            // Assinar o documento PDF com o rodapé adicionado
            logger.info("Assinando o documento com rodapé...");
            sign(pdfWithFooter, outputFile, chain, pk, DigestAlgorithms.SHA256, provider.getName(),
                    PdfSigner.CryptoStandard.CMS, "Assinatura Digital", "Localização Exemplo");

            logger.info("Assinatura concluída com sucesso. Arquivo gerado em: {}", outputFile);

            // Retornar o caminho do arquivo assinado
            //return outputFile;
            
            // Definir o o bucket onde será salvo o arquivo no S3
            String bucket = "portalmseproducao";
            
            // Substituir o arquivo existente no S3
            logger.info("Fazendo upload do arquivo assinado para o S3...");
            String fileUrl = uploadToS3(outputFile, bucket, fileHash+".pdf");

            logger.info("Arquivo assinado enviado com sucesso para o S3. URL do arquivo: {}", fileUrl);

            // Retornar a URL do arquivo assinado no S3
            return fileUrl;
        } catch (Exception e) {
            logger.error("Erro ao processar a assinatura digital: {}", e.getMessage());
            throw new IOException("Erro ao processar a assinatura digital: " + e.getMessage());
        }
    }

    // Método que assina o PDF (original da sua classe)
    public void sign(String srcFilePath, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard signatureType, String reason, String location)
		   throws GeneralSecurityException, IOException {
		
		// Abrir o arquivo PDF localmente
		try (FileInputStream inputStream = new FileInputStream(srcFilePath);
		    FileOutputStream os = new FileOutputStream(dest)) {
		
		   PdfReader reader = new PdfReader(inputStream);
		   PdfSigner signer = new PdfSigner(reader, os, new StampingProperties());
		
		   // Definir aparência da assinatura como invisível
		   PdfSignatureAppearance appearance = signer.getSignatureAppearance();
		   appearance
		           .setReason(reason)
		           .setLocation(location)
		           .setReuseAppearance(false)
		           .setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
		
		   signer.setFieldName("sig");
		
		   // Configuração da assinatura
		   IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
		   IExternalDigest digest = new BouncyCastleDigest();
		
		   // Assinar o PDF
		   signer.signDetached(digest, pks, chain, null, null, null, 0, signatureType);
		}
	}

    // Método para extrair o bucket da URL do S3
    public static String extractBucketFromUrl(String url) {
        try {
            URL s3Url = new URL(url);
            String host = s3Url.getHost(); // Exemplo: "meubucket.s3.amazonaws.com"
            return host.substring(0, host.indexOf('.')); // Extrair o bucket antes do primeiro "."
        } catch (Exception e) {
            throw new RuntimeException("Erro ao extrair bucket da URL: " + e.getMessage());
        }
    }

    // Método para extrair a key (nome do arquivo) da URL do S3
    public static String extractKeyFromUrl(String url) {
        try {
            URL s3Url = new URL(url);
            String path = s3Url.getPath(); // Exemplo: "/meusarquivos/arquivo.pdf"
            return path.substring(path.lastIndexOf('/') + 1); // Pegar o nome do arquivo após a última "/"
        } catch (Exception e) {
            throw new RuntimeException("Erro ao extrair key da URL: " + e.getMessage());
        }
    }


    public String uploadToS3(String file, String bucket, String key) {
        // Definir a região apropriada do seu bucket S3
        Region region = Region.US_EAST_1; // Altere conforme necessário

        // Crie um cliente do S3 com as credenciais do ambiente
        S3Client s3 = S3Client.builder()
                .region(region)
                .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
                .build();

        // Crie o PutObjectRequest para substituir o arquivo no S3
        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(bucket)
                .key(key)  // Mesma chave para substituir o arquivo original
                .cacheControl("no-cache")  // Desabilita o cache para este arquivo
                .build();

        // Faça o upload do arquivo para o S3
        try {
            s3.putObject(putObjectRequest, Paths.get(file));
            System.out.println("Arquivo substituído no S3 com sucesso: " + key);

            // Retorne a URL do arquivo no S3
            String fileUrl = "https://" + bucket + ".s3." + region.id() + ".amazonaws.com/" + key;
            return fileUrl;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Erro ao fazer o upload para o S3: " + e.getMessage());
        }
    }

}
