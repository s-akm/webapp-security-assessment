class AvatarService {
    private static final java.util.Set<String> BANNED_EXTENSIONS = java.util.Set.of("jsp", "war");
    private final String blockedText = "hidden";
    void save(org.springframework.web.multipart.MultipartFile file) {
        String name = file.getOriginalFilename();
    }
}
