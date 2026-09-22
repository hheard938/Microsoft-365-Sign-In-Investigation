Microsoft 365 Sign-In Investigation — Simulated Data
Project Overview
This hands-on Splunk lab investigates a simulated successful sign-in following repeated authentication failures for the same account and IP address. I generated fictional sign-in records, built a query to correlate failures with a later success, tested the detection threshold, and saved the search as a Splunk report. Scope: All records were generated with makeresults. No live Microsoft 365 tenant, Microsoft Entra logs, or client environments were accessed. This project demonstrates investigation logic using simulated data.

Objectives
Analyze failed and successful sign-in sequences
Correlate activity by account and source IP address
Identify a success following five failures within ten minutes
Test activity at and below the detection threshold
Explain why a matching pattern requires further investigation
Document results and proposed SOC triage steps
Tools Used
Splunk Enterprise
Search Processing Language (SPL)
Synthetic sign-in records
Simulated Scenario
Field	Value
Account	lab.user@example.com
Source IP	192.0.2.10
Application label	Office 365 Exchange Online
Matching scenario	Five failures followed by one success
Below-threshold scenario	Four failures followed by one success
Time between records	One minute
The account and IP address are fictional documentation values. The application name is a label in the generated data, not evidence of access to Exchange Online.	
Detection Query
| makeresults count=6
| streamstats count as attempt
| eval _time=now()-(6-attempt)*60
| eval UserPrincipalName="lab.user@example.com",
      IPAddress="192.0.2.10",
      AppDisplayName="Office 365 Exchange Online",
      Outcome=if(attempt<=5,"Failure","Success"),
      DataType="Simulated sign-in data"
| sort 0 _time
| streamstats time_window=10m count(eval(Outcome="Failure")) as PriorFailures by UserPrincipalName IPAddress
| where Outcome="Success" AND PriorFailures>=5
| table _time UserPrincipalName IPAddress AppDisplayName PriorFailures Outcome DataType
How the Query Works
makeresults generates six synthetic records.
streamstats assigns a sequence number to each record.
eval creates timestamps and fictional sign-in fields.
The first five records are marked Failure; the sixth is marked Success.
sort places records in chronological order.
A ten-minute streamstats window counts failures for each account and IP pair.
where returns successful sign-ins with at least five preceding failures in that window. The resulting row represents the successful sign-in. PriorFailures shows the number of preceding failures counted for that account and IP address.
Threshold Validation
Test	Generated records	Expected result	Observed result
At threshold	Five failures, then one success	One matching row	One row with PriorFailures = 5
Below threshold	Four failures, then one success	No matching rows	No results
For the below-threshold test, I changed:			
makeresults count=6 to makeresults count=5
attempt<=5 to attempt<=4 The detection condition remained PriorFailures>=5. These tests validate the count threshold for the generated sequence. They do not validate live log ingestion, scheduled alert delivery, or all possible sign-in patterns.
Saved Splunk Report
Title: Microsoft 365 Simulated Sign-In Investigation The report preserves the synthetic-data query for repeatable practice. Running it generates a new sequence relative to the current time.

Evidence
Successful simulated sign-in following five failures

Analyst Assessment
The query successfully identified the intended failure-to-success sequence. In a real environment, this pattern could reflect a user correcting a password, an application retrying authentication, or unauthorized password guessing followed by access. A match alone does not prove account compromise. Lab classification: Authorized simulated activity. Real-world triage assessment: A matching sequence warrants investigation before classification or escalation.

Proposed SOC Triage Workflow
If this pattern appeared in live sign-in logs:

Confirm the timestamps, account, IP address, application, and authentication results.
Review failure reasons and authentication details.
Check whether the source, device, and application match the user's normal activity.
Review MFA results and available Conditional Access information.
Determine whether other accounts were targeted from the same source.
Examine activity following the successful sign-in.
Validate the activity with the user through an approved channel.
Document findings and escalate according to the organization's runbook when warranted. These are proposed investigation steps. They were not performed against a live tenant in this lab.
Limitations and Tuning Considerations
The query uses a simplified synthetic schema, not an ingested Microsoft Entra data source.
A production query must use the actual source fields and authentication result mappings.
Grouping by account and IP can miss attempts spread across multiple IP addresses.
Shared IP addresses can represent multiple users or devices.
Missing or delayed records can affect sequence analysis.
Five failures is a lab threshold, not a universally appropriate production threshold.
MFA, device, location, risk, and post-sign-in activity were not simulated.
No scheduled alert or automated response was configured.
Skills Demonstrated
SPL query development
Chronological sign-in analysis
Account and IP correlation
Windowed failure counting
Detection-threshold testing
Saved-report creation
Evidence collection
SOC triage reasoning
Clear documentation of simulated work
Final Outcome
The detection returned one matching row for five failures followed by success and no rows for four failures followed by success. This project demonstrates hands-on Splunk analysis of simulated Microsoft 365 sign-in activity.
