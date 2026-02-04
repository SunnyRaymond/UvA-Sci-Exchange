% This function emulates the behavior of a toy server that
% encrypts the plaintext in CBC mode using DES

function [ciphertext] = server_encrypt(plaintext)

% The input size of the block cipher is b=8 bytes
b = 8;

% The server receives plaintexts whose length is variable
plaintext_length = length(plaintext);

% We compute the number of blocks that will be encrypted in CBC mode
no_blocks = ceil(plaintext_length/b);

% Compute the number of padding bytes as specified in PKCS#7
no_padbytes = b - mod(plaintext_length, b);

% Create the padding
padding = repmat(no_padbytes, 1, no_padbytes);

% Concatenate the plaintext and the padding
plaintext = [plaintext padding];

% Partition the plaintext in blocks
plaintext_block = zeros(no_blocks, b);
for i=1:no_blocks
    start_index = (i-1)*b + 1;
    stop_index = i*b;
    plaintext_block(i,:) = plaintext(start_index:stop_index); 
end

% Encrypt in CBC mode

server_key = [12 250 44 11 121 0 7]; % this must be secret

iv = [9 1 53 12 250 0 100 197]; % this must be unpredictable

ciphertext_block = zeros(no_blocks+1, b); % no_blocks + 1 because the IV is attached as the first ciphertext block
ciphertext_block(1,:) = iv;
for i=1:no_blocks
    % xor the ciphtertext block (or the IV) with the plaintext block
    intermediate = bitxor(plaintext_block(i,:), ciphertext_block(i,:));
    % encrypt the intermediate
    ciphertext_block(i+1,:) = DES(intermediate, 'ENC', server_key);
   
end

% concatenate the ciphertext blocks
ciphertext = reshape(ciphertext_block', 1, (no_blocks+1)*b);

  
end
