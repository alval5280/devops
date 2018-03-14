#!/usr/bin/env ruby

# update_aws_cred.rb -- maintain AWS credentials
#
# Copyright (C) 2017 alval5280
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.
#
# The original motivation for creating this script was to maintain >40 accounts
# owned by a single organization. Due to the way Amazon redirects profile URLs
# to a single shared URL and LastPass auto-fill limitations, I determined the
# best "happy medium" betwen security & useability was to use the same password
# for all accounts, then rotate that password and API keys per a standard
# rotation scheme (no greater than 90 days before expiration). This script
# facilitates doing so with minimal effort, once the initial creation and setup
# of API keys in the credentials file for each account/profile is complete.

require 'optparse'
require 'etc'
require 'io/console'
require 'aws-sdk'

# parse optional arguments
usage = "usage: #{File.basename(__FILE__)} [options]"
OPTIONS = { no_password: false, creds_file: nil, provider: nil }
parser = OptionParser.new do |opts|
  opts.banner = usage

  opts.on('-n', '--no-password', "don't change password during run") do |provider|
    OPTIONS[:no_password] = true
  end

  opts.on('-f', '--file creds_file', String, 'path to AWS credentials file') do |creds_file|
    if File.exist?(creds_file)
      OPTIONS[:creds_file] = creds_file
    else
      puts creds_file + " doesn't exist"
      puts opts
      exit 1
    end
  end

  opts.on('-p', '--provider provider', 'single AWS provider to process') do |provider|
    OPTIONS[:provider] = provider
  end

  opts.on('-h', '--help', 'display help') do
    puts opts
    exit
  end
end
parser.parse!

if OPTIONS[:creds_file].nil?
  creds_file = Etc.getpwuid(Process.uid).dir + '/.aws/credentials'
  puts 'Using default AWS credentials file: ' + creds_file
else
  creds_file = OPTIONS[:creds_file]
end

# from https://github.com/aws/aws-sdk-ruby/blob/master/aws-sdk-core/lib/aws-sdk-core/ini_parser.rb
# modified to handle multiple entries for same item
def ini_parse(raw)
  current_profile = nil
  current_prefix = nil
  raw.lines.inject({}) do |acc, line|
    line = line.split(/^|\s;/).first # remove comments
    profile = line.match(/^\[([^\[\]]+)\]\s*(#.+)?$/) unless line.nil?
    if profile
      current_profile = profile[1]
      named_profile = current_profile.match(/^profile\s+(.+?)$/)
      current_profile = named_profile[1] if named_profile
    elsif current_profile
      unless line.nil?
        item = line.match(/^(.+?)\s*=\s*(.+?)\s*$/)
        prefix = line.match(/^(.+?)\s*=\s*$/)
      end
      if item && item[1].match(/^\s+/)
        # Need to add lines to a nested configuration.
        puts current_prefix
        inner_item = line.match(/^\s*(.+?)\s*=\s*(.+?)\s*$/)
        acc[current_profile] ||= {}
        acc[current_profile][current_prefix] ||= {}
        acc[current_profile][current_prefix][inner_item[1]] = inner_item[2]
      elsif item
        # begin modification
        if acc[current_profile] && acc[current_profile][item[1]]
          existing_value = acc[current_profile][item[1]]
          if existing_value.kind_of?(Array)
            acc[current_profile][item[1]] << item[2]
          else
            acc[current_profile][item[1]] = [existing_value, item[2]]
          end
        else
        # end modification
          current_prefix = nil
          acc[current_profile] ||= {}
          acc[current_profile][item[1]] = item[2]
        end
      elsif prefix
        current_prefix = prefix[1]
      end
    end
    acc
  end
end

def ini_build(provider_hash)
  raw = ""
  provider_hash.each_key do |provider|
    raw += "[%s]\n" % provider
    provider_hash[provider].each_key do |key|
      if provider_hash[provider][key].kind_of?(Array)
        if key.eql?('aws_access_key_id')
          provider_hash[provider][key].each_index do |item, idx|
            raw += "aws_access_key_id = %s\n" % item
            raw += "aws_secret_access_key = %s\n" %
              provider_hash[provider]['aws_secret_access_key'][idx]
          end
        end
      else
        raw += "%s = %s\n" % [key, provider_hash[provider][key]]
      end
    end
    raw += "\n"
  end
  raw
end

def process(providers, provider, old_pass, new_pass)
  unless provider.eql?('default') || providers[provider]['region'].nil?
    old_keys = []
    old_secrets = []
    new_keys = []
    new_secrets = []
    if providers[provider]['aws_access_key_id'].kind_of?(Array)
      old_keys = providers[provider]['aws_access_key_id']
      old_secrets = providers[provider]['aws_secret_access_key']
    end

    begin
      iam_client = Aws::IAM::Client.new(profile: provider,
                                        region: providers[provider]['region'])
      puts 'Successfully connected to ' + provider

      client_access_keys = iam_client.list_access_keys
      client_access_keys.access_key_metadata.each do |access_key|
        key_id = access_key.access_key_id
        if access_key.create_date < (Time.now.utc - 90*24*60*60)
          puts key_id + ' is older than 90 days'
          new_key_resp = iam_client.create_access_key()
          new_key_id = new_key_resp.access_key.access_key_id
          new_secret_key = new_key_resp.access_key.secret_access_key
          puts 'New key created with id %s and secret %s' % [new_key_id, new_secret_key]
          if access_key.status == 'Active'
            puts 'Inactivating old access key'
            iam_client.update_access_key({access_key_id: key_id,
                                          status: 'Inactive'})
          end
          puts 'Deleting old access key'
          iam_client.delete_access_key({access_key_id: key_id})
          new_keys << new_key_id
          new_secrets << new_secret_key
        else
          if idx = old_keys.index(key_id)
            new_keys << old_keys[idx]
            new_secrets << old_secrets[idx]
          end
        end
      end

      unless OPTIONS[:no_password]
        iam_client.change_password(old_password: old_pass, new_password: new_pass)
      end
    rescue Aws::IAM::Errors::ServiceError => e
      puts 'Exception for %s:' % provider
      puts "\t%s" % e.to_s
    end
    if new_keys.length > 1
      providers[provider]['aws_access_key_id'] = new_keys
      providers[provider]['aws_secret_access_key'] = new_secrets
    elsif new_keys.length == 1
      providers[provider]['aws_access_key_id'] = new_keys[0]
      providers[provider]['aws_secret_access_key'] = new_secrets[0]
    end
  end
end

raw_content = File.read(creds_file)
aws_providers = ini_parse(raw_content)

unless OPTIONS[:no_password]
  # get old password to set from cli
  print "Enter old password: "
  old_password = STDIN.noecho(&:gets).chomp
  puts
  # get new password to set from cli
  print "Enter new password: "
  new_password = STDIN.noecho(&:gets).chomp
  puts
end

if OPTIONS[:provider].nil?
  aws_providers.each_key do |provider|
    process(aws_providers, provider, old_password, new_password)
  end
else
  passed_provider = OPTIONS[:provider]
  process(aws_providers, passed_provider, old_password, new_password)
end

# rebuild creds file
new_contents = ini_build(aws_providers)
new_file = File.open(creds_file, 'w')
new_file.write(new_contents)
new_file.close()

exit 0
