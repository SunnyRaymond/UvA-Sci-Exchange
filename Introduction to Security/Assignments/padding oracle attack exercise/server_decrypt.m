% This function emulates the behavior of an toy server that
% decrypts the ciphertext in CBC mode

function [pad_error, plaintext] = server_decrypt(ciphertext)


% The input size of the cipher is b=8 bytes
b = 8;

% The server always receives ciphertexts whose length is a multiple of b
% We compute the number of ciphertext blocks that will be decrypted in CBC
% mode
no_blocks = length(ciphertext)/b;

% Partition the ciphertext in blocks
% Note that server receives the IV in the first block of the ciphertext 
ciphertext_block = zeros(no_blocks, b);
for i=1:no_blocks
    start_index = (i-1)*b + 1;
    stop_index = i*b;
    ciphertext_block(i,:) = ciphertext(start_index:stop_index); 
end

% Decrypt in CBC mode
server_key = [12 250 44 11 121 0 7];  % this must be secret
plaintext_block = zeros(no_blocks-1, b); % no_blocks - 1 because the IV is not part of the plaintext blocks
for i=no_blocks-1:-1:1
    % decrypt the block
    intermediate = DES(ciphertext_block(i+1,:), 'DEC', server_key);
    % xor the intermediate with the previous ciphtertext block (or the IV)
    plaintext_block(i,:) =  bitxor(intermediate, ciphertext_block(i,:));
end

% concatenate the plaintext blocks
plaintext = reshape(plaintext_block', 1, (no_blocks-1)*b);


% Padding Check

pad_error = 1;

% Select the final byte of the plaintext
final_byte = plaintext(end);

if final_byte <= b % the 'final byte' cannot be more than b (if that is the case then we have an error)
    
    % Select the last 'final_byte' bytes of the plaintext
    pad_bytes = plaintext(end-final_byte+1:end);
    
    % Check if all pad_bytes are equal to 'final_byte'
    if sum(pad_bytes == final_byte) == final_byte
        pad_error = 0;
    end
    
end

   
end
