package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/tyler-smith/go-bip39"
)

var (
	checkedMu sync.Mutex
	ethClient *ethclient.Client
	err       error
	url       = os.Getenv("ETH_URL")

	// permuteLength dictates how long each string really is
	permuteLength = 2
	wordGroups    = [][]string{
		{
			// Confident
			"police",

			// Not sure
			"hat",
			"art",
			"artwork",
			"oil",
			"piece",
			"canvas",
		},
		{
			// Confident

			// Not Sure
			"woman",
			"gossip",
			"lady",
			"whisper",
			"sister",
		},
		{
			// Confident
			"drum",

			// Not Sure
			"wedding",
			"marriage",
		},
		{
			// Confident

			// Not Sure
			"movie",
			"engage",
			"cover",
			"media",
			// "eagle",
		},
		{
			// Confident

			// Not Sure
			"hope",
			"girl",
			"beauty",
			"nature",
			"flower",
		},
		{
			// Confident
			"window",

			// Not Sure
			"old",
			"open",
			"antique",
			"abandon",
		},
	}
)

type keyStruct struct {
	privateKey *ecdsa.PrivateKey
	mnemonic   string
	balance    uint64
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	start := time.Now()

	ethClient, err = ethclient.Dial(url)
	if err != nil {
		log.Fatal().Err(err).Msg("Error connecting to eth url")
	}
	log.Info().Str("Time", time.Since(start).String()).Str("URL", url).Msg("Client Connected")

	log.Info().Msg("Permuting Word Groups")
	keyChan, errChan := make(chan *keyStruct), make(chan error)
	perm := time.Now()

	permutedGroups := [][][]string{
		permuteWordGroups(wordGroups[0], len(wordGroups[0])),
		permuteWordGroups(wordGroups[1], len(wordGroups[1])),
		permuteWordGroups(wordGroups[2], len(wordGroups[2])),
		permuteWordGroups(wordGroups[3], len(wordGroups[3])),
		permuteWordGroups(wordGroups[4], len(wordGroups[4])),
		permuteWordGroups(wordGroups[5], len(wordGroups[5])),
	}
	uniqueGroups := [][][]string{}
	repeats := 0
	for _, permutedGroup := range permutedGroups {
		found := map[string]bool{}
		unique := [][]string{}
		for _, g := range permutedGroup {
			group := strings.Join(g, " ")
			if !found[group] {
				found[group] = true
				unique = append(unique, g)
			} else {
				repeats++
			}
		}
		uniqueGroups = append(uniqueGroups, unique)
	}
	numberPermutations := 1
	for _, group := range uniqueGroups {
		numberPermutations *= len(group)
	}
	log.Info().Str("Time", time.Since(perm).String()).Int("Removed Repeats", repeats).Msg("Permuted")

	log.Info().
		Int("Possibility Space", numberPermutations).
		Msg("Searching!")

	go joinGroups(
		keyChan, errChan,
		uniqueGroups[0],
		uniqueGroups[1],
		uniqueGroups[2],
		uniqueGroups[3],
		uniqueGroups[4],
		uniqueGroups[5],
	)

	goodKeys := []*keyStruct{}
	var checkBalWait sync.WaitGroup

	foundKeys, errors, invalids, repeats, totalBalance := 0, 0, 0, 0, uint64(0)
	logInterval := numberPermutations / 10

	processStart := time.Now()
	tempPC := time.Now()
	for keysProcessed := 1; keysProcessed <= numberPermutations; keysProcessed++ {
		select {
		case key := <-keyChan:
			keyStr := PrivateKeyString(key.privateKey)
			keyAddr, err := PrivateKeyToAddress(key.privateKey)
			if err != nil {
				log.Error().
					Err(err).
					Str("Private Key", keyStr).
					Msg("Error converting key to address")
			}
			foundKeys++

			if strings.ToLower(keyAddr.Hex()) == strings.ToLower("0xC399bd88A3471bfD277966Fef8e5110857e827Fc") {
				goodKeys = append(goodKeys, key)
				bal, err := checkBalance(keyAddr)
				if err != nil {
					log.Error().Str("Address", keyAddr.Hex()).Str("Key", keyStr).Err(err).Msg("Error checking key balance")
				}
				key.balance = bal
				log.Info().Str("Address", keyAddr.Hex()).Str("Key", keyStr).Msg("JACKPOT!")
			}
			checkBalWait.Add(1)
			go func() {
				defer checkBalWait.Done()
				keyStr := PrivateKeyString(key.privateKey)
				keyAddr, err := PrivateKeyToAddress(key.privateKey)
				if err != nil {
					log.Error().Str("Key", keyStr).Err(err).Msg("Error getting address")
				}
				bal, err := checkBalance(keyAddr)
				if err != nil {
					log.Error().Err(err).Str("Address", keyAddr.Hex()).Str("Key", keyStr).Msg("Error getting key Balance")
				}
				if bal > 0 {
					totalBalance += bal
					key.balance = bal
					goodKeys = append(goodKeys, key)
					log.Info().
						Uint64("Balance", bal).
						Str("Mnemonic", key.mnemonic).
						Str("Address", keyAddr.Hex()).
						Str("Key", keyStr).
						Msg("Found Key!")
				}
			}()
		case err := <-errChan:
			if strings.Contains(err.Error(), "' is not valid") {
				invalids++
			} else {
				errors++
				log.Error().Err(err).Msg("Actual Error!")
			}
		}

		if keysProcessed%logInterval == 0 {
			log.Debug().
				Str("Group Time", time.Since(tempPC).Truncate(time.Millisecond).String()).
				Str("Total Time", time.Since(processStart).Truncate(time.Millisecond).String()).
				Int("Total to Process", numberPermutations).
				Int("Keys Processed", keysProcessed).
				Msg("Progress")
			tempPC = time.Now()
		}
	}

	log.Info().
		Int("Keys Found", foundKeys).
		Int("Errors", errors).
		Int("Invalid Guesses", invalids).
		Int("Repeat Guesses", repeats).
		Uint64("Total Balance", totalBalance).
		Str("Time", time.Since(start).Truncate(time.Millisecond).String()).
		Int("Total Processed", numberPermutations).
		Msg("Finished")

	if len(goodKeys) == 0 {
		log.Warn().Msg("No good keys found :(")
	} else {
		log.Info().Msg("Found Good Keys!")
		for _, goodKey := range goodKeys {
			log.Info().
				Str("Key", PrivateKeyString(goodKey.privateKey)).
				Str("Mnemonic", goodKey.mnemonic).
				Uint64("Balance", goodKey.balance).
				Msg("Good Key")
		}
	}
}

func joinGroups(keyChan chan *keyStruct, errChan chan error, group1, group2, group3, group4, group5, group6 [][]string) {
	for _, f := range group1 {
		firstGroup := f
		go func() {
			for _, s := range group2 {
				secondGroup := s
				go func() {
					for _, t := range group3 {
						thirdGroup := t
						go func() {
							for _, r := range group4 {
								fourthGroup := r
								go func() {
									for _, v := range group5 {
										fifthGroup := v
										go func() {
											for _, sixthGroup := range group6 {
												firstM := strings.Join(firstGroup, " ")
												secondM := strings.Join(secondGroup, " ")
												thirdM := strings.Join(thirdGroup, " ")
												fourthM := strings.Join(fourthGroup, " ")
												fifthM := strings.Join(fifthGroup, " ")
												sixthM := strings.Join(sixthGroup, " ")
												go mnemonicToPrivateKey(
													fmt.Sprintf("%s %s %s %s %s %s", firstM, secondM, thirdM, fourthM, fifthM, sixthM), keyChan, errChan,
												)
											}
										}()
									}
								}()

							}
						}()
					}
				}()
			}
		}()
	}
}

func permuteWordGroups(arr []string, n int) [][]string {
	var helper func([]string, int)
	res := [][]string{}

	helper = func(arr []string, n int) {
		if n == 1 {
			tmp := make([]string, permuteLength)
			copy(tmp, arr[:permuteLength])
			res = append(res, tmp)
		} else {
			for i := 0; i < n; i++ {
				helper(arr, n-1)
				if n%2 == 1 {
					tmp := arr[i]
					arr[i] = arr[n-1]
					arr[n-1] = tmp
				} else {
					tmp := arr[0]
					arr[0] = arr[n-1]
					arr[n-1] = tmp
				}
			}
		}
	}
	helper(arr, len(arr))
	return res
}

func mnemonicToPrivateKey(mnemonic string, keyChan chan *keyStruct, errChan chan error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		errChan <- fmt.Errorf("mnemonic '%s' is not valid", mnemonic)
		return
	}
	seed := bip39.NewSeed(mnemonic, "")
	derivationPath, err := accounts.ParseDerivationPath(`m/44'/60'/0'/0/0`)
	if err != nil {
		errChan <- err
		return
	}

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		errChan <- fmt.Errorf("error building new master key")
		return
	}

	key := masterKey

	for _, path := range derivationPath {
		key, err = key.Derive(path)
		if err != nil {
			errChan <- fmt.Errorf("error deriving master key with path %v", derivationPath)
			return
		}
	}

	privateKey, err := key.ECPrivKey()
	if err != nil {
		errChan <- fmt.Errorf("error converting to private key")
		return
	}

	keyChan <- &keyStruct{
		privateKey: privateKey.ToECDSA(),
		mnemonic:   mnemonic,
	}
	return
}

func checkBalance(address common.Address) (uint64, error) {
	bal, err := ethClient.BalanceAt(context.Background(), address, nil)
	if err != nil {
		return 0, fmt.Errorf("error getting balance at address '%s'", address)
	}
	return bal.Uint64(), nil
}

// PrivateKeyToAddress is a handy converter for an ecdsa private key to a usable eth address
func PrivateKeyToAddress(privateKey *ecdsa.PrivateKey) (common.Address, error) {
	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return common.Address{}, fmt.Errorf(
			"error converting public key to ecdsa format. private key: %s public key: %s", privateKey, privateKey.Public())
	}
	return crypto.PubkeyToAddress(*publicKeyECDSA), nil
}

// PrivateKeyString easy converter of a private key to its hex format
func PrivateKeyString(privateKey *ecdsa.PrivateKey) string {
	return fmt.Sprintf("%x", crypto.FromECDSA(privateKey))
}

func fac(n int) int {
	val := 1
	for i := 1; i <= n; i++ {
		val *= i
	}
	return val
}
