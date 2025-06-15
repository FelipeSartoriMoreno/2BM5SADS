package angl.example.jwt.usuarios;

import angl.example.jwt.auth.LoginRequest;
import angl.example.jwt.auth.LoginResponse;
import angl.example.jwt.auth.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private AuthenticationManager authenticationManager;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UserModel user) {
        if (userRepository.findByEmail(user.getEmail()) != null) {
            return ResponseEntity.badRequest().body("Usuário já existe.");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return ResponseEntity.ok("Usuário registrado com sucesso.");
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        var authenticationToken = new UsernamePasswordAuthenticationToken(
                loginRequest.getEmail(),
                loginRequest.getPassword()
        );

        var authentication = authenticationManager.authenticate(authenticationToken);
        var user = (UserModel) authentication.getPrincipal();
        var token = tokenService.generateToken(user);

        return ResponseEntity.ok(new LoginResponse(token));
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body("Token ausente ou inválido.");
        }

        String token = authHeader.replace("Bearer ", "");
        String login = tokenService.getSubject(token);

        UserModel user = (UserModel) userRepository.findByEmail(login);
        if (user == null) return ResponseEntity.notFound().build();

        return ResponseEntity.ok(user);
    }

    @PutMapping("/me")
    public ResponseEntity<?> updateOwnProfile(
            @RequestBody Map<String, String> body,
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body("Token ausente ou inválido.");
        }

        String token = authHeader.replace("Bearer ", "");
        String email = tokenService.getSubject(token);

        UserModel user = (UserModel) userRepository.findByEmail(email);
        if (user == null) return ResponseEntity.notFound().build();

        if (body.containsKey("nome")) {
            user.setNome(body.get("nome"));
        }
        if (body.containsKey("password")) {
            user.setPassword(passwordEncoder.encode(body.get("password")));
        }

        userRepository.save(user);
        return ResponseEntity.ok("Perfil atualizado com sucesso.");
    }


    @GetMapping("/admin/users")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }

    @PutMapping("/admin/users/{id}")
    public ResponseEntity<?> updateUserByAdmin(@PathVariable Long id, @RequestBody UserModel updatedUser) {
        return userRepository.findById(id)
                .map(user -> {
                    user.setNome(updatedUser.getNome());
                    user.setEmail(updatedUser.getEmail());
                    user.setPassword(passwordEncoder.encode(updatedUser.getPassword()));
                    user.setRole(updatedUser.getRole());
                    userRepository.save(user);
                    return ResponseEntity.ok("Usuário atualizado com sucesso.");
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/admin/users/{id}")
    public ResponseEntity<?> deleteUserByAdmin(@PathVariable Long id) {
        if (!userRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }

        userRepository.deleteById(id);
        return ResponseEntity.ok("Usuário deletado com sucesso.");
    }

}
