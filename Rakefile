require 'bundler/gem_tasks'
require 'rake/extensiontask'
require 'rspec/core/rake_task'

task :build => :compile

Rake::ExtensionTask.new('libssh_ruby') do |ext|
  ext.lib_dir = 'lib/libssh'
end

RSpec::Core::RakeTask.new(:spec)

task :default => %i[clobber compile spec]
