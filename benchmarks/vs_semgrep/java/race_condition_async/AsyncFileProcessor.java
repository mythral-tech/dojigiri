package com.example.race;

import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.*;

@Service
public class AsyncFileProcessor {

    private static final Path UPLOAD_DIR = Paths.get("/var/uploads");

    @Async
    public void processUpload(String username, MultipartFile file)
            throws IOException {
        Path target = UPLOAD_DIR.resolve(file.getOriginalFilename());

        // TOCTOU: check and use are not atomic, race window in async context
        if (Files.exists(target) && !isOwner(target, username)) {
            throw new SecurityException("Not your file");
        }

        // Between the check above and the write below, another async thread
        // can delete the file or replace it with a symlink
        Files.copy(file.getInputStream(), target,
                StandardCopyOption.REPLACE_EXISTING);
    }

    @Async
    public void deleteUpload(String username, String filename)
            throws IOException {
        Path target = UPLOAD_DIR.resolve(filename);

        if (!Files.exists(target) || !isOwner(target, username)) {
            throw new SecurityException("Not your file");
        }

        // Same TOCTOU: between check and delete, file could be swapped
        Files.delete(target);
    }

    private boolean isOwner(Path path, String username) throws IOException {
        return Files.getOwner(path).getName().equals(username);
    }
}
