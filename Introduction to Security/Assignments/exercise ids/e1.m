%% Univariate IDS on KDD99 HTTP (feature #2: src_bytes)
% Requires: create_roc.m (your helper), Statistics Toolbox (for normpdf)

clear; close all; clc;
rng(42, 'twister');

%% ---------- Load dataset (your variables: measurements, labels) ----------
load('KDD99 HTTP dataset.mat');   % contains: measurements (Nx3), labels (Nx1)
X = measurements;                 % features: [duration, src_bytes, dst_bytes]
y = labels;                       % 0 = normal, 1 = intrusion

if size(X,2) ~= 3
    error('Expected X to have 3 features (duration, src_bytes, dst_bytes).');
end
if numel(y) ~= size(X,1)
    error('X and y sizes mismatch.');
end

% Labels
y = y(:);
normal_idx = (y == 0);
intr_idx   = (y == 1);

% Use feature #2 (src_bytes)
X2 = X(:,2);

%% ---------- Train/Test split (unsupervised: train on NORMAL only) ----------
X2_normal = X2(normal_idx);
N_normal  = numel(X2_normal);
N_train   = floor(0.99 * N_normal);

perm      = randperm(N_normal);
train_ix  = perm(1:N_train);
test_ix   = perm(N_train+1:end);

X2_train_normal = X2_normal(train_ix);     % 99% normal for training
X2_test_normal  = X2_normal(test_ix);      % 1% normal for testing
X2_test_intr    = X2(intr_idx);            % all intrusions for testing

%% ---------- Fit Normal model on NORMAL ONLY ----------
mu    = mean(X2_train_normal, 'omitnan');
sigma = std(X2_train_normal,  'omitnan');
if sigma <= eps, sigma = max(sigma, 1e-6); end   % guard against degenerate std

%% ---------- Scores (normal likelihood = higher => more normal) ----------
% Decision used everywhere: predict intrusion if score < threshold
score_normal_test = normpdf(X2_test_normal, mu, sigma);
score_intr_test   = normpdf(X2_test_intr,   mu, sigma);

%% ---------- ROC (uses your create_roc.m) ----------
[TP_pts, FP_pts] = create_roc(score_normal_test(:).', score_intr_test(:).');
AUC = trapz(FP_pts, TP_pts);
fprintf('AUC (univariate, feature #2) = %.6f\n', AUC);

%% ---------- Pick threshold via Youden''s J (TP - FP) ----------
[TP2, FP2, TH] = compute_roc_with_thresholds(score_normal_test, score_intr_test);
[bestJ, bestIdx] = max(TP2 - FP2);
best_th = TH(bestIdx);
fprintf('Best threshold (Youden J max): th = %.6g, TP=%.4f, FP=%.4f, J=%.4f\n', ...
    best_th, TP2(bestIdx), FP2(bestIdx), bestJ);

%% ---------- Confusion rates at chosen threshold ----------
TP = mean(score_intr_test   < best_th);
FP = mean(score_normal_test < best_th);
FN = 1 - TP;
TN = 1 - FP;

TP_count = sum(score_intr_test   < best_th);
FP_count = sum(score_normal_test < best_th);
FN_count = sum(score_intr_test   >= best_th);
TN_count = sum(score_normal_test >= best_th);

fprintf('\nAt selected threshold:\n');
fprintf('TP=%.4f, FP=%.4f, TN=%.4f, FN=%.4f\n', TP, FP, TN, FN);

precision  = TP_count / (TP_count + FP_count);
recall     = TP_count / numel(score_intr_test);
accuracy   = (TP_count + TN_count) / (numel(score_intr_test) + numel(score_normal_test));
F1         = 2 * (precision * recall) / (precision + recall);
specificity = TN_count / (TN_count + FP_count);

fprintf('Precision=%.4f  Recall=%.4f  F1=%.4f  Accuracy=%.4f  Specificity=%.4f\n', ...
    precision, recall, F1, accuracy, specificity);

%% ---------- Diagnostics (optional) ----------
figure; 
tiledlayout(2,1);
nexttile;
histogram(X2_train_normal, 80, 'Normalization','pdf'); hold on;
xx = linspace(min(X2_train_normal), max(X2_train_normal), 1000);
plot(xx, normpdf(xx, mu, sigma), 'LineWidth', 1.5);
title('Training normals: fitted N(\mu,\sigma) vs. histogram');
xlabel('src\_bytes'); ylabel('pdf'); grid on;
nexttile;
histogram(X2_test_normal, 80, 'Normalization','pdf'); hold on;
plot(xx, normpdf(xx, mu, sigma), 'LineWidth', 1.5);
title('Test normals: check fit holds');
xlabel('src\_bytes'); ylabel('pdf'); grid on;

%% ---------- Local helper ----------
function [TP, FP, TH] = compute_roc_with_thresholds(score_normal, score_intrusion)
    scores_all = [score_normal(:); score_intrusion(:)];
    TH = unique(sort(scores_all, 'ascend'));
    nN = numel(score_normal); nI = numel(score_intrusion);
    TP = zeros(size(TH)); FP = zeros(size(TH));
    for k = 1:numel(TH)
        th = TH(k);
        TP(k) = sum(score_intrusion < th) / nI;
        FP(k) = sum(score_normal   < th) / nN;
    end
    % add endpoints
    if TH(1) > -inf, TH = [-inf; TH(:)]; TP = [0; TP(:)]; FP = [0; FP(:)]; end
    if TH(end) < inf, TH = [TH(:); inf]; TP = [TP(:); 1]; FP = [FP(:); 1]; end
end
