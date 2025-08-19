package edu.icet.ecom.service.impl;

import edu.icet.ecom.dto.UserDTO;
import edu.icet.ecom.entity.UserEntity;
import edu.icet.ecom.repository.UserRepository;
import edu.icet.ecom.service.UserService;
import edu.icet.ecom.service.JWTService;
import javax.persistence.EntityNotFoundException;
import javax.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.modelmapper.ModelMapper;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private static final String UPPERCASE_PATTERN = ".*[A-Z].*";
    private static final String LOWERCASE_PATTERN = ".*[a-z].*";
    private static final String DIGIT_PATTERN = ".*\\d.*";

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;
    @Override
    @Transactional
    public void createUser(UserDTO userDTO) {
        String validationResult = validateUser(userDTO);
        if (validationResult != null) {
            throw new IllegalArgumentException(validationResult);
        }
        userDTO.setPassword(passwordEncoder.encode(userDTO.getPassword()));


        try {
            UserEntity user = modelMapper.map(userDTO, UserEntity.class);
            userRepository.save(user);
            log.info("User created successfully with ID: {}", user.getId());
        } catch (DataIntegrityViolationException e) {
            log.error("Error creating user: {}", e.getMessage());
            throw new DataIntegrityViolationException("Error creating user", e);
        }
    }

    @Override
    public UserDTO getUserById(Long id) {
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));
        return modelMapper.map(user, UserDTO.class);
    }

    @Override
    @Transactional
    public void updateUser(Long id, UserDTO userDTO) {
        String validationResult = validateUser(userDTO);
        if (validationResult != null) {
            throw new IllegalArgumentException(validationResult);
        }

        UserEntity existingUser = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));

        if (userDTO.getPassword() != null) {
            userDTO.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        }
        modelMapper.map(userDTO, existingUser);
        userRepository.save(existingUser);
        log.info("User updated successfully with ID: {}", id);
    }

    @Override
    @Transactional
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new EntityNotFoundException("User not found with id: " + id);
        }
        userRepository.deleteById(id);
        log.info("User deleted successfully with ID: {}", id);
    }

    @Override
    public List<UserDTO> getAllUsers() {
        return userRepository.findAll().stream()
                .map(user -> modelMapper.map(user, UserDTO.class))
                .collect(Collectors.toList());
    }

    @Override
    public UserDTO getUserByEmail(String email) {
        UserEntity user = userRepository.findByemail(email);
        if (user == null) {
            throw new EntityNotFoundException("User not found with email: " + email);
        }
        return modelMapper.map(user, UserDTO.class);
    }

    @Override
    public String validateUser(UserDTO userDTO) {
        Long id = userDTO.getId();
        String username = userDTO.getUsername();
        String fullname = userDTO.getFullname();
        String email = userDTO.getEmail();
        String password = userDTO.getPassword();
        String confirmPassword = userDTO.getConfirmPassword();
        Date dateOfBirth = userDTO.getDateOfBirth();
        String phoneNumber = userDTO.getPhoneNumber();

        // Validate email
        if (email == null || email.isEmpty() || !email.matches("^[\\w.+-]+@[\\w-]+\\.[a-zA-Z]{2,}$")) {
            return "Invalid email format.";
        }

        // Validate password requirement for new users
        if (id == null && password == null) {
            return "Password is required for new users.";
        }

        // Validate password if provided
        if (password != null && !isValidPassword(password, confirmPassword)) {
            return getPasswordValidationError(password, confirmPassword);
        }

        // Validate fullname
        if (fullname == null || fullname.length() < 3) {
            return "Name must be at least 3 characters.";
        }

        // Validate username
        if (username == null || username.length() < 3) {
            return "username must be at least 3 characters.";
        }

        // Validate date of birth
        if (dateOfBirth == null) {
            return "Date of Birth must be in the format YYYY-MM-DD.";
        }

        // Validate phone number
        if (phoneNumber == null || !phoneNumber.matches("^\\d{10}$")) {
            return "Phone number must be exactly 10 digits.";
        }

        // Check for duplicate email on new user creation
        if (id == null) {
            UserEntity existingUser = userRepository.findByemail(email);
            if (existingUser != null) {
                return "Email is already in use.";
            }
        }

        return null;
    }

    private boolean isValidPassword(String password, String confirmPassword) {
        return password.length() >= 8 &&
               password.matches(UPPERCASE_PATTERN) &&
               password.matches(LOWERCASE_PATTERN) &&
               password.matches(DIGIT_PATTERN) &&
               password.equals(confirmPassword);
    }

    private String getPasswordValidationError(String password, String confirmPassword) {
        if (password.length() < 8) {
            return "Password must be at least 8 characters.";
        }
        if (!password.matches(UPPERCASE_PATTERN)) {
            return "Password must contain at least one uppercase letter.";
        }
        if (!password.matches(LOWERCASE_PATTERN)) {
            return "Password must contain at least one lowercase letter.";
        }
        if (!password.matches(DIGIT_PATTERN)) {
            return "Password must contain at least one digit.";
        }
        if (!password.equals(confirmPassword)) {
            log.info(password + " " + confirmPassword);
            return "Passwords do not match.";
        }
        return null;
    }

    @Override
    public void authenticateUser(String email, String password) {
        UserEntity user = userRepository.findByemail(email);
        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("Invalid email or password.");
        }
        log.info("User authenticated successfully: {}", email);
    }

    @Override
    public void forgotPassword(String password, String confirmPassword, String newPassword) {

        if (password == null || confirmPassword == null || newPassword == null) {
            throw new IllegalArgumentException("Password fields cannot be null.");
        }

        if (!password.equals(confirmPassword)) {
            throw new IllegalArgumentException("Current password and confirm password do not match.");
        }

        if (newPassword.length() < 8) {
            throw new IllegalArgumentException("New password must be at least 8 characters.");
        }

        if (!newPassword.matches(UPPERCASE_PATTERN) || !newPassword.matches(LOWERCASE_PATTERN) || !newPassword.matches(DIGIT_PATTERN)) {
            throw new IllegalArgumentException("New password must contain at least one uppercase letter, one lowercase letter, and one digit.");
        }

        // Here you would typically update the user's password in the database
        // For this example, we will just log the action
        log.info("Password reset successfully for user with current password: {}", password);

    }



    public String verify(UserDTO user) {

        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword()));

        if (authenticate.isAuthenticated())
            return jwtService.generateToken(user.getEmail());

        return "User is not authenticated";

    }

}