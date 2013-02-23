#!/usr/bin/perl
use strict;
use XML::Twig;
use Data::Dumper;
use Term::ANSIColor;
use feature 'state';

my @packets_all;
my $twig_handlers = { 'packet' => \&packet_inc };
my $compact = 0;
my $changes = 0;
for (my $i = 0; $i < @ARGV; $i++) {
	if ($ARGV[$i] =~ /--compact/) {
		$compact = 1;
		splice @ARGV, $i, 1;
		$i--;
	} elsif ($ARGV[$i] =~ /--changes/) {
		$changes = 1;
		splice @ARGV, $i, 1;
		$i--;
	}
}

if (lc $ARGV[0] eq 'diff') {
	die "Need 2 filenames.\n" if @ARGV < 3;
	my $pcap1 = XML::Twig->new(TwigHandlers => { 'packet' => \&packet1_inc });
	$pcap1->parsefile($ARGV[1]);
	my $pcap2 = XML::Twig->new(TwigHandlers => { 'packet' => \&packet2_inc });
	$pcap2->parsefile($ARGV[2]);
	print packet_diff();
} elsif (lc $ARGV[0] eq 'analyze') {
	die "Need 1 filename.\n" if @ARGV < 2;
	my $pcap1 = XML::Twig->new(TwigHandlers => { 'packet' => \&packet1_inc });
	$pcap1->parsefile($ARGV[1]);
	print packet_analyze();
} elsif (lc $ARGV[0] eq 'duplex') {
	die "Need 2 filenames.\n" if @ARGV < 3;
	my $pcap1 = XML::Twig->new(TwigHandlers => { 'packet' => \&packet1_inc });
	$pcap1->parsefile($ARGV[1]);
	my $pcap2 = XML::Twig->new(TwigHandlers => { 'packet' => \&packet2_inc });
	$pcap2->parsefile($ARGV[2]);
	print packet_duplex();
} else {
	die "Options are analyze, duplex, or diff.\n";
}

sub packet_analyze {
	my ($g) = @_;
	$g = 0 unless defined $g;
	foreach my $packet (@{$packets_all[$g]}) {
		line_print($packet);
	}
}

sub packet_duplex {
	my ($g) = @_;
	$g = 0 unless defined $g;

	my $count = 0;
	while ($count < @{$packets_all[$g]}) {
		my $pac_grp = 0;
		while ($pac_grp < @packets_all) {
			line_print($packets_all[$pac_grp]->[$count], 1)
				if defined $packets_all[$pac_grp]->[$count];
			$pac_grp++;
		}
		$count++;
	}
}

sub packet_diff {
#	TODO: This is currently broken
#	die "You need to have the same number of packets in the two files.\n"
#		if @packets1 != @packets2;
#	my $count = 0;
#	while ($count < @packets1) {
#		my $packet1 = $packets1[$count];
#		my $packet2 = $packets2[$count];
#		if (defined $packet1->{'data'} or defined $packet2->{'data'}) {
#			if ($packet1->{'data'} ne $packet2->{'data'}) {
#				line_print($packet1, 1);
#				line_print($packet2, 2);
#			}
#		}
#		$count++;
#	}
}

#sub find_longest_chain {
#	my ($packet) = @_;
#}
#sub categorize {
#	my ($packet) = @_;
#	#my $prev_packet = ...;
#	#my $next_packet = ...;
#
#
#	return -1;
#}
#my @bg_colors = ();

sub data_diff {
	my ($data1, $data2) = @_;
	my @d1 = split ':', $data1;
	my @d2 = split ':', $data2;
	my $size1 = @d1;
	my $size2 = @d2;
	my $count = 0;
	while ($count < $size1 and $count < $size2) {
		if ($d1[$count] ne $d2[$count]) {
			$d1[$count] = color('red')
				. $d1[$count]
				. color('reset');
		} else {
			$d1[$count] = color('reset')
				. $d1[$count];
		}
		$count++;
	}
	return join ':', @d1;
}

sub packet_sig_single {
	my ($packet) = @_;
	return $packet->{'urb_type'}
		. $packet->{'direction'}
		. $packet->{'endpoint'}
		. $packet->{'data_length'};
}
sub packet_sig_full {
	my ($packet) = @_;
	my $prev_packet = $packets_all[$packet->{'group'}]->[$packet->{'num'}-1];
	my $next_packet = $packets_all[$packet->{'group'}]->[$packet->{'num'}+1];
	my $tail = ((defined $prev_packet ? packet_sig_single($prev_packet) : '')
			. (defined $next_packet ? packet_sig_single($next_packet) : ''));

	return packet_sig_single($packet) . $tail;
}

sub color_changes {
	state %memory;
	my ($packet) = @_;
	my $out = $packet->{'data'};
	my $lookup = packet_sig_full($packet);
	if (defined $memory{$lookup}) {
		if ($memory{$lookup} ne $packet->{'data'}) {
			$out = data_diff($packet->{'data'}, $memory{$lookup});
			$memory{$lookup} = $packet->{'data'};
		} else {
			$out = color('dark white')
				. $packet->{'data'}
				. color('reset');
		}
	} else {
		$memory{$lookup} = $packet->{'data'};
	} return $out;
}

sub line_print {
	my ($packet, $cap_num) = @_;
	my $flag = 0;
	if (($packet->{'direction'} and $packet->{'urb_type'} eq 'URB_SUBMIT')
		or (!$packet->{'direction'} and $packet->{'urb_type'}
							eq 'URB_COMPLETE')) {
		return if ($compact);
		$flag = 1;
	}
	print color 'dark white';

	#print color $bg_colors[$s] unless (my $s = categorize($packet)) < 0;
	my ($ldigit) = $packet->{'endpoint'} =~ /(.)$/;

	print pad_front($packet->{'num'}, length(@{$packets_all[0]}))
		, color('dark white')
		,' : '
		, (defined $cap_num ? "CAP$cap_num : " : '')
		, color('green')
		, pad_end($packet->{'urb_type'}, 12)
		, (!$flag ? color 'reset' : '')
		, color('dark white')
		, ' : '
		, (!$packet->{'direction'} ? color 'dark yellow' : color 'bold blue')
		, $ldigit x ' '
		, $packet->{'endpoint'}
			, ($packet->{'direction'} ? '->' : '<-')
			, 'HOST : '
		, (defined $packet->{'data'}
			? ($changes == 1 ? color_changes($packet)
				     : $packet->{'data'})
			: '[NONE]')
		, "\n";
	print color 'reset';
}

sub pad_front {
	my ($thing, $amount) = @_;
	return (' ' x ($amount - length $thing)) . $thing;
}
sub pad_end{
	my ($thing, $amount) = @_;
	return $thing . (' ' x ($amount - length $thing));
}

sub packet_inc {
	my ($packets_group, $packet) = @_;
	my ($num) = $packet->get_xpath(q!proto[@name='geninfo']/field[@name='num']!);
	$num = $num->{'att'}->{'show'};

	my ($usb) = $packet->get_xpath(q!proto[@name='usb']!);
	my ($endpoint) = $usb->get_xpath(q!field[@name='usb.endpoint_number']!);
	$endpoint = $endpoint->{'att'}->{'show'};
	my ($urb_type) = $usb->get_xpath(q!field[@name='usb.urb_type']!);
	($urb_type) = $urb_type->{'att'}->{'showname'} =~ /URB type: (.*) \(/;
	my $direction = ($endpoint =~ /0x8/) ? 1 : 0;
	my ($data) = $usb->get_xpath(q!field[@name='usb.data']!);
	$data = $data->{'att'}->{'show'};
	my ($data_length) = $usb->get_xpath(q!field[@name='usb.data_len']!);
	$data_length = $data_length->{'att'}->{'show'};

	my $packet_hash = {
		num => $num,
		endpoint => $endpoint,
		direction => $direction,
		urb_type => $urb_type,
		data => $data,
		group => $packets_group,
		data_length => $data_length
	};
	push @{$packets_all[$packets_group]}, $packet_hash;
}
sub packet1_inc {
	my ($twig, $packet) = @_;
	packet_inc(0, $packet);
}
sub packet2_inc {
	my ($twig, $packet) = @_;
	packet_inc(1, $packet);
}

