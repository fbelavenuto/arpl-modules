# CPUfreq governors
#obj-$(CONFIG_CPU_FREQ_GOV_PERFORMANCE)	+= cpufreq_performance.o
#obj-$(CONFIG_CPU_FREQ_GOV_POWERSAVE)	+= cpufreq_powersave.o
obj-m	+= cpufreq_userspace.o
obj-m	+= cpufreq_ondemand.o
obj-m	+= cpufreq_conservative.o
#obj-$(CONFIG_CPU_FREQ_GOV_COMMON)		+= cpufreq_governor.o

# CPUfreq cross-arch helpers
#obj-$(CONFIG_CPU_FREQ_TABLE)		+= freq_table.o

#obj-$(CONFIG_GENERIC_CPUFREQ_CPU0)	+= cpufreq-cpu0.o

##################################################################################
# x86 drivers.
# Link order matters. K8 is preferred to ACPI because of firmware bugs in early
# K8 systems. This is still the case but acpi-cpufreq errors out so that
# powernow-k8 can load then. ACPI is preferred to all other hardware-specific drivers.
# speedstep-* is preferred over p4-clockmod.

#obj-$(CONFIG_X86_ACPI_CPUFREQ)		+= acpi-cpufreq.o mperf.o
#obj-$(CONFIG_X86_POWERNOW_K8)		+= powernow-k8.o
#obj-$(CONFIG_X86_PCC_CPUFREQ)		+= pcc-cpufreq.o
#obj-$(CONFIG_X86_POWERNOW_K6)		+= powernow-k6.o
#obj-$(CONFIG_X86_POWERNOW_K7)		+= powernow-k7.o
#obj-$(CONFIG_X86_LONGHAUL)		+= longhaul.o
#obj-$(CONFIG_X86_E_POWERSAVER)		+= e_powersaver.o
#obj-$(CONFIG_ELAN_CPUFREQ)		+= elanfreq.o
#obj-$(CONFIG_SC520_CPUFREQ)		+= sc520_freq.o
#obj-$(CONFIG_X86_LONGRUN)		+= longrun.o
#obj-$(CONFIG_X86_GX_SUSPMOD)		+= gx-suspmod.o
#obj-$(CONFIG_X86_SPEEDSTEP_ICH)		+= speedstep-ich.o
#obj-$(CONFIG_X86_SPEEDSTEP_LIB)		+= speedstep-lib.o
#obj-$(CONFIG_X86_SPEEDSTEP_SMI)		+= speedstep-smi.o
#obj-$(CONFIG_X86_SPEEDSTEP_CENTRINO)	+= speedstep-centrino.o
#obj-$(CONFIG_X86_P4_CLOCKMOD)		+= p4-clockmod.o
#obj-$(CONFIG_X86_CPUFREQ_NFORCE2)	+= cpufreq-nforce2.o
#obj-m	+= intel_pstate.o
#obj-$(CONFIG_X86_AMD_FREQ_SENSITIVITY)	+= amd_freq_sensitivity.o
