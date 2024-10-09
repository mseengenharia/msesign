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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.GeneralSecurityException;

@RestController
public class DigitalSignatureController {

    private static final Logger logger = LoggerFactory.getLogger(DigitalSignatureController.class);

    private final DigitalSignatureExample assinatura;

    // Injeção de dependência para `DigitalSignatureExample`
    @Autowired
    public DigitalSignatureController(DigitalSignatureExample assinatura) {
        this.assinatura = assinatura;
    }

    @GetMapping("/assinar")
    public String assinarDocumento(@RequestParam String url) {
        // Obter as variáveis de ambiente
        String keystorePath = System.getenv("PFX_CERT_PATH");
        String password = System.getenv("PFX_CERT_PASSWORD");

        // Verificar se as variáveis de ambiente estão definidas
        if (keystorePath == null || password == null) {
            logger.error("Variáveis de ambiente PFX_CERT_PATH e PFX_CERT_PASSWORD não estão definidas.");
            return "Erro: Variáveis de ambiente PFX_CERT_PATH e PFX_CERT_PASSWORD devem ser definidas.";
        }

        logger.info("Iniciando processo de assinatura para o documento na URL: {}", url);
        logger.info("Usando keystorePath: {}", keystorePath);

        try {
            // Chamar o método para assinar o documento
            String resultado = assinatura.signDocument(keystorePath, password, url);
            logger.info("Documento assinado com sucesso e enviado ao S3. URL: {}", resultado);
            return "Documento assinado e enviado ao S3 com sucesso. URL: " + resultado;
        } catch (GeneralSecurityException | IOException e) {
            logger.error("Erro ao assinar o documento: {}", e.getMessage());
            return "Erro ao assinar o documento: " + e.getMessage();
        }
    }
}
