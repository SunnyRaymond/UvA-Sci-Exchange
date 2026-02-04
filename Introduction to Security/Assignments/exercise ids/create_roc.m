function [TP, FP] = create_roc(score_normal, score_intrusion)


% testset scores
scores = [score_normal score_intrusion];

% testset labels
labels = [zeros(1,length(score_normal)) ones(1,length(score_intrusion))];

% compute the number of intrusions and number of normal datapoints in the
% two testsets
no_intrusions = length(score_intrusion);
no_normal = length(score_normal);

% sort the IDS scores
[sorted_score, sorted_indexes] = sort(scores,'ascend');

% sort the respective labels
sorted_label = labels(sorted_indexes);

% iterate over all sorted scores
TP_count = 0;
FP_count = 0;
previous_score = min(scores)-1; % initialized to a value smaller than all scores
counter = 1;
for i=1:length(sorted_score)
 
    % extra check to account for score value repetitions
    if abs(sorted_score(i)-previous_score) > 10^(-6)
       
        % generate ROC point
        % the previous score acts like a threshol
        TP_count = sum(score_intrusion < previous_score);
        FP_count = sum(score_normal < previous_score);

        TP(counter) = TP_count/no_intrusions;
        FP(counter) = FP_count/no_normal;
        previous_score = sorted_score(i);
        counter = counter + 1;
    end    
  
end

% this is ROC point (1,1)
TP(counter) = TP_count/no_intrusions;
FP(counter) = FP_count/no_normal;


% plot the ROC
figure;
plot(FP, TP, '-o', 'LineWidth', 1.5);
xlabel('False Positive FP', 'FontSize', 13);
ylabel('True Positive TP', 'FontSize', 13);
title('ROC curve - efficient computation', 'FontSize', 14);

end