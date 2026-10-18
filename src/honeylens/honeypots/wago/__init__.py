"""WAGO PFC200 WBM / CODESYS / WebVisu decoy (Idea 54).

Ported from the standalone `wago_rtu` service. The process simulation and the page
set are carried over; event emission is replaced by the HoneyLens log contract in
`honeypots/hp_wago.py`, so this package holds no database credentials and stays
container-ready.
"""
