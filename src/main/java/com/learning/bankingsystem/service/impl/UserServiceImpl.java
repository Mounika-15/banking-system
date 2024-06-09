package com.learning.bankingsystem.service.impl;

import com.learning.bankingsystem.dto.JwtAuthResponseDto;
import com.learning.bankingsystem.dto.LoginDto;
import com.learning.bankingsystem.dto.OpenAccountDto;
import com.learning.bankingsystem.entity.*;
import com.learning.bankingsystem.exception.FoundException;
import com.learning.bankingsystem.exception.InvalidInputException;
import com.learning.bankingsystem.mapper.AddressMapper;
import com.learning.bankingsystem.mapper.OccupationMapper;
import com.learning.bankingsystem.mapper.UserMapper;
import com.learning.bankingsystem.repository.*;
import com.learning.bankingsystem.security.JwtTokenProvider;
import com.learning.bankingsystem.service.UserService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    private final PasswordRepository passwordRepository;

    private final UserRoleRepository userRoleRepository;

    private final OccupationRepository occupationRepository;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private final AuthenticationManager authenticationManager;

    private final JwtTokenProvider jwtTokenProvider;

    private final UserMapper userMapper;

    private final AddressMapper addressMapper;

    private final OccupationMapper occupationMapper;

    private final AddressRepository addressRepository;

    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private static final int PASSWORD_LENGTH = 10;

    private static final long INITIAL_ACCOUNT_NUMBER = 100000000000L;

    private final Random random = new SecureRandom();

    private final JavaMailSender mailSender;

    private final TemplateEngine templateEngine;

    @Value("${default.send.email}")
    String defaultEmail;


    @Override
    public JwtAuthResponseDto login(LoginDto loginDto) {
        var user = userRepository.findByEmail(loginDto.getEmail());
        if (user == null) {
            throw new UsernameNotFoundException("User not found for email: " + loginDto.getEmail());
        }

        var password = passwordRepository.findByUser_UuidAndStatus(user.getUuid(), PasswordStatus.ACTIVE);
        if (password == null) {
            throw new InvalidInputException("RESET_PASSWORD", "Password not found for user: " + loginDto.getEmail() + ". Please reset you password ");
        }
        if (user.getProfileStatus().equals(ProfileStatus.PENDING)) {
            throw new InvalidInputException("ADMIN_APPROVAL_PENDING", "Your account not approved by Admin");
        }

        var userRoles = userRoleRepository.findByUser_Uuid(user.getUuid());

        if (!passwordEncoder.matches(loginDto.getPassword(), password.getPassword())) {
            if (password.getInvalidPasswordEntryCount() >= 2) {
                password.setStatus(PasswordStatus.EXPIRED);
                passwordRepository.save(password);
                throw new InvalidInputException("MAXIMUM_TRIES_REACHED", "You have entered incorrect password for 3 times, Reset your password now to login");
            }
            password.setInvalidPasswordEntryCount(password.getInvalidPasswordEntryCount() + 1);
            passwordRepository.save(password);
            throw new InvalidInputException("INCORRECT_PASSWORD", "Entered password is incorrect");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword())
        );

        var roles = userRoles.stream()
                .map(userRole -> userRole.getRole().toString())
                .toList();

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtTokenProvider.generateToken(authentication);

        return JwtAuthResponseDto.builder()
                .accessToken(token)
                .userId(user.getUuid())
                .tokenType("Bearer")
                .roles(roles)
                .build();
    }

    public void openAccount(OpenAccountDto openAccountDto) {
        if (userRepository.findByEmail(openAccountDto.getEmail()) != null) {
            throw new FoundException("USER_ALREADY_EXISTS", "User already exists with email: " + openAccountDto.getEmail());
        }

        var user = userMapper.openAccountDtoToUser(openAccountDto);
        user.setProfileStatus(ProfileStatus.PENDING);
        user.setAccountNumber(generateAccountNumber());

        var savedUser = userRepository.save(user);

        var residentialAddress = addressMapper.addressDtoTOAddress(openAccountDto.getResidentialAddress());
        residentialAddress.setAddressType(AddressType.RESIDENTIAL);
        residentialAddress.setUser(savedUser);
        addressRepository.save(residentialAddress);

        var permanentAddress = addressMapper.addressDtoTOAddress(openAccountDto.getPermanentAddress());
        permanentAddress.setAddressType(AddressType.PERMANENT);
        permanentAddress.setUser(savedUser);
        addressRepository.save(permanentAddress);

        var generatedPassword = generateRandomPassword();
        var password = Password.builder()
                .user(savedUser)
                .password(passwordEncoder.encode(generatedPassword))
                .status(PasswordStatus.ACTIVE)
                .invalidPasswordEntryCount(0)
                .build();
        passwordRepository.save(password);

        userRoleRepository.save(UserRole.builder()
                .user(savedUser)
                .role(RoleType.USER)
                .build());

        var occupation = occupationMapper.occupationDtoToOccupation(openAccountDto.getOccupation());
        occupation.setUser(savedUser);
        occupationRepository.save(occupation);

        sendOpenAccountEmail(savedUser.getUuid(), generatedPassword);
    }

    private String generateAccountNumber() {
        long count = userRepository.count();
        return String.format("%012d", INITIAL_ACCOUNT_NUMBER + count + 1);
    }

    private String generateRandomPassword() {
        StringBuilder sb = new StringBuilder(PASSWORD_LENGTH);

        for (int i = 0; i < PASSWORD_LENGTH; i++) {
            int index = random.nextInt(CHARACTERS.length());
            sb.append(CHARACTERS.charAt(index));
        }

        return sb.toString();
    }

    private void sendOpenAccountEmail(UUID userId, String password) {
        Thread thread = new Thread(() -> {
            var user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with ID: " + userId));

            try {
                MimeMessage message = mailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(message);

                var emailTemplateName = "open-account-mail";
                var emailTemplate = "Open Account Successful";
                helper.setFrom(defaultEmail, emailTemplate);
                helper.setTo(user.getEmail());
                helper.setSubject(emailTemplate);

                Context context = new Context();
                context.setVariable("name", user.getFirstName() + " " + user.getLastName());
                context.setVariable("accountNumber", user.getAccountNumber());
                context.setVariable("email", user.getEmail());
                context.setVariable("phoneNumber", user.getMobileNumber());
                context.setVariable("password", password);

                helper.setText(templateEngine.process(emailTemplateName, context), true);

                mailSender.send(message);
            } catch (MessagingException | UnsupportedEncodingException e) {
                log.error("Error sending email to user: {}", userId, e);
            }
        });
        thread.start();
    }
}
