% DFA assignment
clear all;
close all;

% load the faulty ciphtexts, the fault-free ciphertexts and the true
% key of round 16 from the file 'assignment_dfa.mat'
load assignment_dfa.mat;

% --- wiring helpers (auto-detect correct DES wiring; no extra files added) ---
function P = invert_permutation(Pinv)
P = zeros(1,32);
for ii = 1:32
    P(Pinv(ii)) = ii;
end
end

function cnt = count_candidates_for_box1(Cj, Cpj, useRL, usePinv)
% useRL: if true, interpret invFP output as [R16 L16]; else [L16 R16]
% usePinv: if true, use P^{-1}(Delta_R16) on RHS; else use Delta_R16 directly.
    if useRL
        R16  = Cj(1:32);   L16  = Cj(33:64);
        R16p = Cpj(1:32);  L16p = Cpj(33:64);
    else
        L16  = Cj(1:32);   R16  = Cj(33:64);
        L16p = Cpj(1:32);  R16p = Cpj(33:64);
    end

    Delta_R16 = xor(R16, R16p);
    EL  = expansion(L16);
    ELp = expansion(L16p);

    Pinv_Delta = inverse_feistel_permutation(Delta_R16);

    % S-box 1 slice helpers (re-use same indexing scheme as main)
    E_idx = @(i) (6*(i-1)+1):(6*i);
    Sout_idx = @(i) (4*(i-1)+1):(4*i);

    rhs = Pinv_Delta(Sout_idx(1));
    if ~usePinv
        rhs = Delta_R16(Sout_idx(1)); % try without P^{-1}
    end

    EiL  = EL(E_idx(1));
    EiLp = ELp(E_idx(1));

    cnt = 0;
    for k = 0:63
        kbits = dec_to_bits(k,6);
        s_out_clean  = sboxf(xor(EiL , kbits), 1);
        s_out_faulty = sboxf(xor(EiLp, kbits), 1);
        if isequal(xor(s_out_clean, s_out_faulty), rhs)
            cnt = cnt + 1;
        end
    end
end


% try to locate the variables in the MAT file in a tolerant way
% expected: two matrices of size n×64 (fault-free C, faulty Cprime), and a 48-bit round key
vars = whos;
cipher_names = {};
key_name = '';
for t = 1:numel(vars)
    v = vars(t);
    if ismember(numel(v.size), [2 3]) && v.size(end) == 64
        cipher_names{end+1} = v.name; %#ok<AGROW>
    elseif v.size(1) * v.size(end) == 48
        key_name = v.name;
    end
end
assert(numel(cipher_names) >= 2, 'Could not find two 64-bit ciphertext arrays in assignment_dfa.mat');
% Heuristics: the first is fault-free, the second is faulted. Adjust if needed.
C_clean  = eval(cipher_names{1});
C_faulty = eval(cipher_names{2});
if isempty(key_name)
    warning('True round-16 key not found in MAT. Proceeding without final equality check.');
    K16_true = [];
else
    K16_true = eval(key_name);
    K16_true = K16_true(:).'; % row vector
end

% normalize to numeric {0,1} row-vectors
if islogical(C_clean),  C_clean  = double(C_clean);  end
if islogical(C_faulty),C_faulty = double(C_faulty); end

% repeat the process for n ciphertext pairs (C,C')
n = size(C_clean, 1);

% for i-th S-box we will keep a running set of surviving key candidates (0..63)
survivors = cell(1,8);
for i = 1:8
    survivors{i} = 0:63; % start with all 6-bit keys possible
end

% DES constants for slicing
E_idx = @(i) (6*(i-1)+1):(6*i);     % 6-bit chunk for S-box i after expansion
Sout_idx = @(i) (4*(i-1)+1):(4*i);  % 4-bit chunk for S-box i before P (i.e., P^{-1} output)

% Build P from P^{-1} (in case we need it)
Pinv_table = [ ...
     9 17 23 31 13 28  2 18 ...
    24 16 30  6 26 20 10  1 ...
     8 14 25  3  4 29 11 19 ...
    32 12 22  7  5 27 15 21];
P_table = invert_permutation(Pinv_table);

% Probe the first pair to choose wiring:
C1  = inverse_final_permutation(C_clean(1,:));
C1p = inverse_final_permutation(C_faulty(1,:));

% Try all four combinations: [R|L]×{use P^{-1} on ΔR16, or not}
combos = [ true  true;   true  false;   false true;   false false];
scores = zeros(1,4);
for t = 1:4
    scores(t) = count_candidates_for_box1(C1, C1p, combos(t,1), combos(t,2));
end
[~,bestIdx] = max(scores);
useRL   = combos(bestIdx,1);
usePinv = combos(bestIdx,2);

if scores(bestIdx) == 0
    warning('Auto-detect could not find any consistent wiring on the first pair. Proceeding with default [R|L] and P^{-1}.');
    useRL = true; usePinv = true;
else
    fprintf('Auto-detected wiring: [%s | %s], RHS uses %s(ΔR16). Candidates for S1 on first pair: %d\n', ...
        ternary(useRL,'R16,L16','L16,R16'), ternary(useRL,'(invFP as [R L])','(invFP as [L R])'), ...
        ternary(usePinv,'P^{-1}','identity'), scores(bestIdx));
end

function out = ternary(cond,a,b)
if cond, out=a; else, out=b; end
end


for j = 1:n
    % for j=1:n

        % apply the inverse final permutation on C and C'
        Cj  = inverse_final_permutation(C_clean(j,:));
        Cpj = inverse_final_permutation(C_faulty(j,:));
        
        % split the C and C' to left and right parts [L16, R16] and [L16', R16']
        if useRL
            % interpret invFP output as [R16, L16]
            R16  = Cj(1:32);   L16  = Cj(33:64);
            R16p = Cpj(1:32);  L16p = Cpj(33:64);
        else
            % interpret invFP output as [L16, R16]
            L16  = Cj(1:32);   R16  = Cj(33:64);
            L16p = Cpj(1:32);  R16p = Cpj(33:64);
        end
        
        % compute the fault differential Delta_R16 = R16 XOR R16'
        Delta_R16 = xor(R16, R16p);
        
        % compute the expansion E(L16)
        EL  = expansion(L16);
        
        % compute the expansion E(L16')
        ELp = expansion(L16p);
        
        % apply the inverse permutation P to the fault differential
        Pinv_Delta = inverse_feistel_permutation(Delta_R16);

    
        % for all 8 DES sboxes
        % for i=1:8
        for i = 1:8
    
            % in 'candidates' we will collect the correct key candidates
            % according to DFA equation
            % candidates = []; % initially the candidate list is empty
            candidates = [];
    
            % for all 2^6 key candidates of K_{16}^i
            % for k = 0:2^6-1
            for k = 0:(2^6-1)
    
                % select the parts corresponding to sbox Si
    
                % P^{-1}_{i}(Delta_R16) 
                if usePinv
                    Delta_i = Pinv_Delta(Sout_idx(i));   % 4-bit differential at S-box i output
                else
                    % some datasets encode DFA with Δ at S-box output pre-P; try identity
                    Delta_i = Delta_R16(Sout_idx(i));
                end

                
                % E_{i}(L16)
                EiL  = EL(E_idx(i));   % 6-bit input to S-box i (clean)
    
                % E_{i}(L16')
                EiLp = ELp(E_idx(i));  % 6-bit input to S-box i (faulted)
    
                % Compute the left and right part of the DFA equation and check
                % if the equation holds
                kbits = dec_to_bits(k, 6);
                s_out_clean  = sboxf(xor(EiL , kbits), i);
                s_out_faulty = sboxf(xor(EiLp, kbits), i);
                lhs = xor(s_out_clean, s_out_faulty);   % 4 bits
                rhs = Delta_i;                           % 4 bits
    
                % if the key candidate agrees with the DFA equation then keep, 
                % otherwise discard it
                if isequal(lhs, rhs)
                    candidates(end+1) = k; %#ok<AGROW>
                end
            end
    
            % For the first pair (C,C'), keep all valid key candidates.  
            % For the following pairs update the list of possible K_{16}^i
            % candidates by using intersection
            if j == 1
                survivors{i} = candidates;
            else
                survivors{i} = intersect(survivors{i}, candidates);
            end
        end
end

% build recovered round key K16 (48 bits) from survivors: if multiple remain, pick all or the first
K16_rec = zeros(1,48);
ambiguous = false;
for i = 1:8
    if isempty(survivors{i})
        error('No surviving key candidates for S-box %d. Check inputs/order.', i);
    end
    if numel(survivors{i}) > 1
        ambiguous = true;
    end
    kpick = survivors{i}(1);            % pick the first surviving candidate
    K16_rec(E_idx(i)) = dec_to_bits(kpick, 6);
end

fprintf('Recovered K16 (48 bits):\n');
disp(K16_rec);

if ~isempty(K16_true)
    % Finally, check if the recovered 16th roundkey of DES matches the true
    % 16th round key loaded from 'assignment_dfa.mat'
    eq = isequal(K16_rec(:).', K16_true(:).');
    fprintf('Match with provided true K16: %s\n', string(eq));
    if ~eq
        fprintf('Note: Either multiple candidates remain or variable ordering differs.\n');
    end
end
if ambiguous
    fprintf('Warning: Some S-boxes still have multiple surviving candidates; first was chosen.\n');
end

% --- helpers ---
function bits = dec_to_bits(d, w)
% Convert nonnegative integer d to row vector of w bits (MSB first)
b = dec2bin(d, w) - '0';
bits = double(b);
end
