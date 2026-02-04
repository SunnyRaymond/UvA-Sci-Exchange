clear all; % this clears all data from your workplace
close all; % this closes all windows with plots

% The adversary intercepts the following ciphtertext:
ciphertext = [9,1,53,12,250,0,100,197,53,78,68,24,117,47,223,246,150,148,220,255,68,209,56,247];

% The ciphertext contains the IV and 2 ciphertext blocks C1 and C2
% Each block has 8 bytes since we are using DES in CBC mode
iv = ciphertext(1:8);
c1 = ciphertext(9:16);
c2 = ciphertext(17:24);


% Using the ciphertext and the padding oracle function, recover the
% last byte of the plaintext [Last Byte Oracle]

% We must create a malicious ciphertext 
% -the last ciphertext block (c2) must be constant
% -the ciphertext block before the last one (c1_prime) is initialized as random and we vary its last byte
% Use the function randi() to generate 8 random bytes and store them in
% c1_prime
c1_prime = randi([0,255],1,8,'uint16');  % random 8 bytes (0..255)

% for all possible values of a byte (value x ranging from 0 until 255)
found = false;
for x = 0:255
    
    % Set the last byte of c1_prime to x
    c1_try = c1_prime;
    c1_try(8) = x;
    
    % Concatenate the IV, c1_prime and c2 producing a malicious ciphertext 
    % mc
    mc = [iv, c1_try, c2];
    
    % Ask the oracle if the malicious ciphertext mc results in a padding 
    % error or not
    pad_ok = oracle(mc);   % 1 == valid PKCS#7 padding, 0 == padding error
    
    % If the padding is correct the correct x and break outside
    % the loop
    if pad_ok == 1
        found = true;
        x_hit = x;          % the value of the last byte that yields valid padding
        c1_star = c1_try;   % keep the winning block we sent
        break
    end
    
    % Otherwise (if there is a padding error), keep trying values of x 
    
% end of the loop
end


% Compute the last byte of the intermediate i2 using the value of x that
% produced a correct padding
i2_lastbyte = bitxor(uint16(c1_star(8)), uint16(1));

% Use the last byte of the original ciphertext block c1 to compute the last
% byte of p2
p2_lastbyte = bitxor(i2_lastbyte, uint16(c1(8)));
fprintf('Recovered last byte of P2: 0x%02X\n', p2_lastbyte)

% Normally, you don't have access to the server_decrypt() function (it kinda
% defeats the purpose of any attack :D). However, just uncomment the following to
% check if your padding oracle attack got the right plaintext byte:
[padding_error, p2_correct] = server_decrypt(ciphertext);
p2_correct_lastbyte = p2_correct(16);
sanity_check = p2_correct_lastbyte == p2_lastbyte;
fprintf('Sanity check: %d\n', sanity_check);


% Optional part: Gradually recover the rest of the bytes of plaintext block P2
% ...
    

% Optional part: Perform the extra check for the other paddings
% ...

    