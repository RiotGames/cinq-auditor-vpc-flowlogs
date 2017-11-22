*************************
cinq-auditor-vpc-flowlogs
*************************

===========
Description
===========

This auditor validates that VPC flow logging is enabled within all your VPCs for your account, taking corrective action if necessary.

Please check out the `README <https://github.com/RiotGames/cloud-inquisitor/blob/master/docs/backend/README.rst>`_ 
for further details on the how ``cinq-auditor-vpc-flowlogs`` works with further details on ``Cloud Inquisitor`` backend is built and what technologies we use.

=====================
Configuration Options
=====================

+------------------+----------------+--------+-----------------------------------------------------------------------------------------------------------+
| Option name      | Default Value  | Type   | Description                                                                                               |
+==================+================+========+===========================================================================================================+
| enabled          | False          | bool   | Enable the VPC Flow Logs auditor                                                                          |
+------------------+----------------+--------+-----------------------------------------------------------------------------------------------------------+
| interval         | 60             | int    | Run frequency in minutes                                                                                  |
+------------------+----------------+--------+-----------------------------------------------------------------------------------------------------------+
