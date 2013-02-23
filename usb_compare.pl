#!/usr/bin/perl
use Modern::Perl;
use GitLike::Dispatch;
use XML::Twig;
use Data::Dumper;
use Term::ANSIColor;

my @packets_all;
my $twig_handlers = { packet => \&packet_inc };

my $dispatch = GitLike::Dispatch->new(
    alias   => {
        help    => sub {
            my $self = shift;
            print "Possible commands:\n", map {"\t$_\n"} $self->find_commands();
            print STDERR qq{
                Flags:
                    --compact\t\tUse compact formatting in output
                    --changes\t\tHighlight differences in successive packets
            }
        },
        diff    => sub {
            die "Need 2 filenames.\n" if @ARGV < 3;
            my $pcap1 = XML::Twig->new(TwigHandlers => { packet => \&packet1_inc });
            $pcap1->parsefile($ARGV[1]);
            my $pcap2 = XML::Twig->new(TwigHandlers => { packet => \&packet2_inc });
            $pcap2->parsefile($ARGV[2]);
            print packet_diff();
        },
        analyze => sub {
            die "Need 1 filename.\n" if @ARGV < 2;
            my $pcap1 = XML::Twig->new(TwigHandlers => { packet => \&packet1_inc });
            $pcap1->parsefile($ARGV[1]);
            print analyze_packet();
        },
        duplex  => sub {
            die "Need 2 filenames.\n" if @ARGV < 3;
            my $pcap1 = XML::Twig->new(TwigHandlers => { packet => \&packet1_inc });
            $pcap1->parsefile($ARGV[1]);
            my $pcap2 = XML::Twig->new(TwigHandlers => { packet => \&packet2_inc });
            $pcap2->parsefile($ARGV[2]);
            print packet_duplex();
        },
    },
);

sub analyze_packet {
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

sub data_diff {
	my ($data1, $data2) = @_;
	my @d1 = split ':', $data1;
	my @d2 = split ':', $data2;
	my $size1 = @d1;
	my $size2 = @d2;
	my $count = 0;
	while ($count < $size1 and $count < $size2) {
		if ($d1[$count] ne $d2[$count]) {
			$d1[$count] = color('red') . $d1[$count] . color('reset');
		} else {
			$d1[$count] = color('reset') . $d1[$count];
		}
		$count++;
	}
	return join ':', @d1;
}

sub packet_sig_single {
	my ($packet) = @_;
	return $packet->{'urb_type'} . $packet->{'direction'}
		 . $packet->{'endpoint'} . $packet->{'data_length'};
}
sub packet_sig_full {
	my ($packet) = @_;
	my $prev = $$packets_all[$$packet{'group'}][$$packet{'num'} - 1];
	my $next = $$packets_all[$$packet{'group'}][$$packet{'num'} + 1];
    return packet_sig_single($packet)
        . (defined $prev ? packet_sig_single($prev) : '')
        . (defined $next ? packet_sig_single($next) : '');
}

sub line_print {
	my ($packet, $cap_num) = @_;
	my $flag = 0;
	if (($packet->{'direction'} and $packet->{'urb_type'} eq 'URB_SUBMIT')
		or (!$packet->{'direction'} and $packet->{'urb_type'}
							eq 'URB_COMPLETE')) {
		return if ($config{compact});
		$flag = 1;
	}
	print color 'dark white';

	#print color $bg_colors[$s] unless (my $s = categorize($packet)) < 0;
	my ($ldigit) = $packet->{'endpoint'} =~ /(.)$/;

	print pad_front($packet->{'num'}, scalar @{$packets_all[0]})
		, color('dark white'), ' : ', (defined $cap_num ? "CAP$cap_num : " : '')
		, color('green'), pad_end($$packet{urb_type}, 12), ($flag or color 'reset')
		, color('dark white'), ' : '
		, color($$packet{direction} ? 'bold blue' : 'dark yellow')
		, $ldigit x ' ', $$packet{endpoint}
			, ($$packet{direction} ? '->' : '<-')
			, 'HOST : '
		, (defined $packet->{'data'}
			? ($config{changes} == 1 ? colored_changes($packet)
				                     : $$packet{data})
			: '[NONE]'), "\n";
	print color 'reset';
}

sub colored_changes {
	state %memory;
	my ($packet) = @_;
	my $out = $packet->{'data'};
	my $lookup = packet_sig_full($packet);
	if (defined $memory{$lookup}) {
		if ($memory{$lookup} ne $$packet{data}) {
			$out = data_diff($$packet{data}, $memory{$lookup});
			$memory{$lookup} = $$packet{data};
		} else {
			$out = color('dark white') . $$packet{data} . color('reset');
		}
	} else {
		$memory{$lookup} = $$packet{data};
	} return $out;
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
	$num = $$num{att}{show};

	my ($usb) = $packet->get_xpath(q!proto[@name='usb']!);
	my ($endpoint) = $usb->get_xpath(q!field[@name='usb.endpoint_number']!);
	$endpoint = $$endpoint{att}{show};
	my ($urb_type) = $usb->get_xpath(q!field[@name='usb.urb_type']!);
	($urb_type) = $$urb_type{att}{showname} =~ /URB type: (.*) \(/;
	my $direction = ($endpoint =~ /0x8/);
	my ($data) = $usb->get_xpath(q!field[@name='usb.data']!);
	$data = $$data{att}{show};
	my ($data_length) = $usb->get_xpath(q!field[@name='usb.data_len']!);
	$data_length = $$data_length{att}{show};

	push @{$packets_all[$packets_group]}, {
		num => $num,
		endpoint => $endpoint,
		direction => $direction,
		urb_type => $urb_type,
		data => $data,
		group => $packets_group,
		data_length => $data_length
	};
}
sub packet1_inc {
	my ($twig, $packet) = @_;
	packet_inc(0, $packet);
}
sub packet2_inc {
	my ($twig, $packet) = @_;
	packet_inc(1, $packet);
}

