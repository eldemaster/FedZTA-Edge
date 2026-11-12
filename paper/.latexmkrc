# Create any missing .bib files (owned by other workers) so bibtex never fails.
for my $b (qw(refs refs_intro refs_background refs_system refs_evaluation refs_security)) {
    unless (-e "$b.bib") { open(my $fh, '>', "$b.bib") and close($fh); }
}
$pdf_mode = 1;
$bibtex_use = 1;
