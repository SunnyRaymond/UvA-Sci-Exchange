% This function emulates the padding oracle function of the server

function oracle_reply = oracle(ciphertext)

% if the padding is correct, the oracle returns 1, else it returns 0
oracle_reply = ~server_decrypt(ciphertext);

end