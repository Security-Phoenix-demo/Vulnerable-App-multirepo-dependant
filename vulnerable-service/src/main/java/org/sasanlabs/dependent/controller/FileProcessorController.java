package org.sasanlabs.dependent.controller;

import org.sasanlabs.dependent.service.VulnerableAppClient;
import org.sasanlabs.dependent.service.DataProcessingService;
import org.sasanlabs.shared.model.FileMetadata;
import org.sasanlabs.shared.sanitizer.InputValidator;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

/**
 * File processing controller with path traversal and upload relay.
 * Pattern 2 + 3: Relay uploads to VulnerableApp, use shared FileMetadata model.
 */
@RestController
@RequestMapping("/api/files")
public class FileProcessorController {

    private final VulnerableAppClient client;
    private final DataProcessingService processingService;

    private static final String LOCAL_UPLOAD_DIR = "/tmp/vulnerable-service-uploads";

    public FileProcessorController(VulnerableAppClient client,
                                    DataProcessingService processingService) {
        this.client = client;
        this.processingService = processingService;
    }

    /**
     * Uploads file locally using shared FileMetadata model.
     * VULNERABLE: FileMetadata.getFullPath() allows path traversal (Pattern 3).
     * VULNERABLE: InputValidator.isValidFilename() has bypass issues (Pattern 1).
     * Cross-repo taint: user filename → shared lib validator → shared model → file write.
     */
    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {
        try {
            String originalFilename = file.getOriginalFilename();

            // "Validate" with shared library — broken validator
            if (!InputValidator.isValidFilename(originalFilename)) {
                return ResponseEntity.badRequest().body("Invalid filename");
            }

            // Create metadata using shared model — path traversal via getFullPath()
            FileMetadata metadata = new FileMetadata(
                    originalFilename, file.getContentType(), file.getSize());
            metadata.setBaseDir(LOCAL_UPLOAD_DIR);

            // VULNERABLE: getFullPath() concatenates without traversal check
            Path targetPath = Paths.get(metadata.getFullPath());
            Files.createDirectories(targetPath.getParent());
            Files.copy(file.getInputStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);

            return ResponseEntity.ok("Uploaded to: " + metadata.getFullPath());
        } catch (IOException e) {
            return ResponseEntity.internalServerError().body("Upload failed: " + e.getMessage());
        }
    }

    /**
     * Relays file upload to VulnerableApp.
     * VULNERABLE: Forwards user-uploaded file directly to backend (Pattern 2).
     * Cross-repo taint: user file → this service → HTTP multipart → VulnerableApp upload handler.
     */
    @PostMapping("/relay")
    public ResponseEntity<String> relayUpload(
            @RequestParam("file") MultipartFile file,
            @RequestParam(defaultValue = "LEVEL_1") String level) {
        try {
            String result = client.uploadFile(
                    "/UnrestrictedFileUpload/" + level,
                    file.getBytes(),
                    file.getOriginalFilename()
            );
            return ResponseEntity.ok(result);
        } catch (IOException e) {
            return ResponseEntity.internalServerError().body("Relay failed: " + e.getMessage());
        }
    }

    /**
     * Reads a file using shared FileMetadata.
     * VULNERABLE: User controls filename → path traversal via FileMetadata.getFullPath().
     * Cross-repo taint: user filename → shared model → file read.
     */
    @GetMapping("/read")
    public ResponseEntity<String> readFile(@RequestParam String filename) {
        FileMetadata metadata = new FileMetadata(filename, "text/plain", 0);
        metadata.setBaseDir(LOCAL_UPLOAD_DIR);
        try {
            Path filePath = Paths.get(metadata.getFullPath());
            String content = new String(Files.readAllBytes(filePath));
            return ResponseEntity.ok(content);
        } catch (IOException e) {
            return ResponseEntity.notFound().build();
        }
    }
}
