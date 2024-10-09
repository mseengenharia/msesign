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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class DigitalsigningspringApplication {

    private static final Logger logger = LoggerFactory.getLogger(DigitalsigningspringApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(DigitalsigningspringApplication.class, args);
    }

    @Bean
    public CommandLineRunner run(DigitalSignatureExample signer) {
        return args -> {
            if (args.length > 0) {
                // Carregar valores das variáveis de ambiente
                String keystorePath = System.getenv("PFX_CERT_PATH");  // Variável de ambiente para o caminho do certificado
                String password = System.getenv("PFX_CERT_PASSWORD");  // Variável de ambiente para a senha

                // Verificar se as variáveis de ambiente estão definidas
                if (keystorePath == null || password == null) {
                    logger.error("Variáveis de ambiente PFX_CERT_PATH e PFX_CERT_PASSWORD devem ser definidas.");
                    throw new IllegalArgumentException("Variáveis de ambiente PFX_CERT_PATH e PFX_CERT_PASSWORD não estão definidas.");
                }

                logger.info("Iniciando processo de assinatura com URL: {}", args[0]);
                logger.info("Usando keystorePath: {}", keystorePath);

                // A URL passada como argumento
                String url = args[0];

                try {
                    // Chamar o método de assinatura
                    String resultado = signer.signDocument(keystorePath, password, url);
                    logger.info("Processo de assinatura concluído com sucesso. Resultado: {}", resultado);
                } catch (Exception e) {
                    logger.error("Erro ao assinar o documento: {}", e.getMessage());
                    e.printStackTrace();
                }
            } else {
                logger.warn("Nenhum argumento de URL foi passado.");
            }
        };
    }
}
