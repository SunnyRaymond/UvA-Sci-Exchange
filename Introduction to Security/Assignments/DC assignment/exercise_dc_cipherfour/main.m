% Differential Cryptanalysis on CipherFour
clear all;
close all;

% Generate a few thousand 16-bit plaintexts pairs
% Each plaintext can be organized as 4 nibbles: [a b c d] 
% Note that a nibble is a 4-bit value
% Ensure that the difference between every plaintext pair (m0,m1) is 
% equal to (0 0 2 0)
no_pairs = 3000;
m0 = randi(16, no_pairs, 4) - 1;  
m1 = m0;
m1(:,3) = bitxor(m0(:,3), 2);         % set difference (0 0 2 0)

% for all generated plaintext pairs 
kept_c0 = []; kept_c1 = []; kept_idx = 0;
for i = 1:no_pairs
    
    % compute the respective ciphertext pairs using the cipher_four()
    % implementation
    c0 = cipher_four(m0(i,:));
    c1 = cipher_four(m1(i,:));
    
    % apply filtering to the ciphertext pairs i.e. 
    % -compute the difference between the ciphertext pairs
    delta_c = bitxor(c0, c1);
    
    % -check if this difference could be originating from a correct pair
    % the correct pairs are: (0 0 h 0) where h is in {1,2,9,10} 
    if delta_c(1)==0 && delta_c(2)==0 && delta_c(4)==0 && ismember(delta_c(3), [1 2 9 10])

    % -if the ciphertext pair passes the filter's check, we keep it
    % otherwise, we discard it
        kept_idx = kept_idx + 1;
        kept_c0(kept_idx, :) = c0;
        kept_c1(kept_idx, :) = c1;
    end
    
end

% focus on the 3rd nibble of the ciphertext pairs that were kept after
% filtering
num_kept = size(kept_c0,1);

% initalize the counter for all key candidates to zero
key_counter = zeros(1,16);

% for all ciphertexts that remain after filtering
for i = 1:num_kept

    % for all key guesses of the 3rd nible of roundkey k6 
    for key_guess = 0:15
        
        % invert the 6th addkey operation
        x0 = bitxor(kept_c0(i,3), key_guess);
        x1 = bitxor(kept_c1(i,3), key_guess);
        
        % invert the sbox
        y0 = inv_sbox(x0);
        y1 = inv_sbox(x1);
        
        % compute the difference delta
        delta = bitxor(y0, y1);
        
        % compare the delta with the difference (0 0 2 0)
        % if they are equal then increment the the respective key counter
        % by one
        if delta == 2
            key_counter(key_guess+1) = key_counter(key_guess+1) + 1;
        end
        
    end

end

% find which key guess has the largest counter 
[max_val, max_index] = max(key_counter);

% print and store the recovered key nibble
k6_nibble3_recovered = max_index - 1;
fprintf('Recovered k6 nibble 3 = %d\n', k6_nibble3_recovered);

% you can also confirm by comparing it to the correct key nibble in
% cipher_four()
% (true k6 third nibble in cipher_four.m is 12)
fprintf('Is recovered nibble equal to true nibble (12)? %d\n', k6_nibble3_recovered == 12);

% visualize with a bar plot the counters for the k6 key guesses
bar(0:15, key_counter);
xlabel('k6 third-nibble guess (0..15)');
ylabel('Counter (matches of \Delta after inv sbox == 2)');
title('Counters for k6 third-nibble guesses (CipherFour)');
grid on;
