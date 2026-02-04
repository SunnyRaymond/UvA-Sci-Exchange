clear all;
close all;


% IDS TRAINING PHASE

% load the training dataset that contains:
% -a dataset captured during normal behavior (dataset_nointrusion)
% -a dataset captured during an intrusion (dataset_intrusion)
load('dataset_normal_ids_training.mat');

% use the datasets to train two normal distibutions by computing the mean
% and standard deviation 
mu_nointrusion = mean(dataset_nointrusion_train);
sigma_nointrusion = std(dataset_nointrusion_train);
mu_intrusion = mean(dataset_intrusion_train);
sigma_intrusion = std(dataset_intrusion_train);

% plot the two distributions for values (0,20)
x = linspace(0,20,5000);
% compute the likelihood for both distributions in the interval (0,20)
% using the normal probability density function
pdf_nointrusion = normpdf(x, mu_nointrusion, sigma_nointrusion);
pdf_intrusion = normpdf(x, mu_intrusion, sigma_intrusion);
% generate the likelihood plot
figure; 
plot(x, pdf_nointrusion, 'LineWidth', 1.5); hold on;
hold on;
plot(x, pdf_intrusion, 'LineWidth', 1.5);
hold off; 
xlabel('Time Units', 'FontSize', 13);
ylabel('Likelihood', 'FontSize', 13);
legend('No Intrusion', 'Intrusion', 'FontSize', 13);


%--------------------------------------------------------------------------

% IDS TEST PHASE

% load the test dataset that contains:
% -a dataset captured during normal behavior (dataset_nointrusion_test)
% -a dataset captured during an intrusion (dataset_intusion_test)
load('dataset_normal_ids_testing');

% For every element in the 'no intrusion' testset, compute the likelihood
% that it matches to the 'no intrusion' model and then to the 'intrusion' 
% model. Subsequently decide which model is the best match. Count the
% number of true negatives and false positives.
TN_counter = 0;
FP_counter = 0;
total_number_nointrusions = length(dataset_nointrusion_test);
for i=1:total_number_nointrusions
    
    current_element = dataset_nointrusion_test(i);
    
    score_nointrusion = normpdf(current_element, mu_nointrusion, sigma_nointrusion);
    score_intrusion = normpdf(current_element, mu_intrusion, sigma_intrusion);
    
    if score_nointrusion > score_intrusion
        TN_counter = TN_counter + 1;
    else
        FP_counter = FP_counter + 1;
    end
    
end
% Compute the true negative rate TN
TN = TN_counter/total_number_nointrusions;
% Compute the false positive rate FP 
FP = 1 - TN;

% For every element in the intrusion testset, compute the likelihood
% that it matches to the 'no intrusion' model and then to the 'intrusion' 
% model. Subsequently decide which model is the best match. Count the
% number of true positives and false negatives.
TP_counter = 0;
FN_counter = 0;
total_number_intrusions = length(dataset_intrusion_test);
for i=1:total_number_intrusions
    
    current_element = dataset_intrusion_test(i);
    
    score_nointrusion = normpdf(current_element, mu_nointrusion, sigma_nointrusion);
    score_intrusion = normpdf(current_element, mu_intrusion, sigma_intrusion);
    
    if score_nointrusion < score_intrusion
        TP_counter = TP_counter + 1;
    else
        FN_counter = FN_counter + 1;
    end
    
end
% Compute the true positive rate TP 
TP = TP_counter/total_number_intrusions;
% Compute the false negative rate FN
FN =  1 - TP;

% Compute additional IDS performance metrics
precision = TP_counter/(TP_counter + FP_counter);
recall = TP_counter/total_number_intrusions;
accuracy = (TP_counter + TN_counter)/(total_number_intrusions + total_number_nointrusions);
F_measure = 2/(1/precision + 1/recall);
specificity = TN_counter/(FP_counter + TN_counter);

% Create the confusion matrix
confusion_matrix = [TP_counter FP_counter; FN_counter TN_counter];
confusion_matrix_rates = [TP FP; FN TN];
% visualize the confusion matrix rates using a heatmap
figure;
xlabels = {'Intrusion','No Intrusion'};
ylabels = {'Intrusion','No Intrusion'};
h = heatmap(xlabels, ylabels, confusion_matrix_rates);
h.XLabel = 'True Class';
h.YLabel = 'Classifier Decision';




